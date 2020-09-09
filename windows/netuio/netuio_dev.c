/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Microsoft Corporation.
 */

#include <stdio.h>
#include "netuio_drv.h"

#include <wdmguid.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, netuio_create_device)
#pragma alloc_text (PAGE, netuio_map_hw_resources)
#pragma alloc_text (PAGE, netuio_free_hw_resources)
#endif

static NTSTATUS
get_pci_device_info(_In_ WDFOBJECT device)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    PNETUIO_CONTEXT_DATA  ctx;
    ctx = netuio_get_context_data(device);

    if (!ctx)
        return status;

    ctx->wdf_device = device;  // Store for later use

    // Obtain the BUS_INTERFACE_STANDARD interface from the Bus Driver
    status = WdfFdoQueryForInterface(device, &GUID_BUS_INTERFACE_STANDARD,
        (PINTERFACE)&ctx->bus_interface,
        sizeof(BUS_INTERFACE_STANDARD), 1, NULL);
    if (!NT_SUCCESS(status))
        return status;

    // Retrieve the B:D:F details of our device
    PDEVICE_OBJECT pdo = NULL;
    pdo = WdfDeviceWdmGetPhysicalDevice(device);
    if (pdo) {
        ULONG prop = 0, length = 0;
        status = IoGetDeviceProperty(pdo, DevicePropertyBusNumber, sizeof(ULONG), (PVOID)&ctx->addr.bus_num, &length);
        status = IoGetDeviceProperty(pdo, DevicePropertyAddress, sizeof(ULONG), (PVOID)&prop, &length);

        if (NT_SUCCESS(status)) {
            ctx->addr.func_num = prop & 0x0000FFFF;
            ctx->addr.dev_num = ((prop >> 16) & 0x0000FFFF);
        }
    }

    return status;
}

static NTSTATUS
create_device_specific_symbolic_link(_In_ WDFOBJECT device)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING netuio_symbolic_link;

    PNETUIO_CONTEXT_DATA  ctx;
    ctx = netuio_get_context_data(device);

    if (!ctx)
        return status;

    // Build symbolic link name as <netuio_symbolic_link>_BDF  (bus/device/func)
    CHAR  symbolic_link[64] = { 0 };
    sprintf_s(symbolic_link, sizeof(symbolic_link), "%s_%04d%02d%02d",
        NETUIO_DEVICE_SYMBOLIC_LINK_ANSI, ctx->addr.bus_num,
        ctx->addr.dev_num, ctx->addr.func_num);

    ANSI_STRING ansi_symbolic_link;
    RtlInitAnsiString(&ansi_symbolic_link, symbolic_link);

    status = RtlAnsiStringToUnicodeString(&netuio_symbolic_link, &ansi_symbolic_link, TRUE);
    if (!NT_SUCCESS(status))
        return status;

    status = WdfDeviceCreateSymbolicLink(device, &netuio_symbolic_link);

    RtlFreeUnicodeString(&netuio_symbolic_link);

    return status;
}

/*
Routine Description:
    Worker routine called to create a device and its software resources.

Return Value:
    NTSTATUS
 */
_Use_decl_annotations_
NTSTATUS
netuio_create_device(PWDFDEVICE_INIT DeviceInit)
{
    NTSTATUS status;
    WDFDEVICE device = NULL;

    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDF_PNPPOWER_EVENT_CALLBACKS pnpPowerCallbacks;
    WDF_FILEOBJECT_CONFIG fileConfig;
    WDF_OBJECT_ATTRIBUTES fileAttributes;

    PAGED_CODE();

    // Register PnP power management callbacks
    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);
    pnpPowerCallbacks.EvtDevicePrepareHardware = netuio_evt_prepare_hw;
    pnpPowerCallbacks.EvtDeviceReleaseHardware = netuio_evt_release_hw;
    WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPowerCallbacks);

    // Register callbacks for when a HANDLE is opened or closed.
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&fileAttributes, NETUIO_FILE_CONTEXT_DATA);
    WDF_FILEOBJECT_CONFIG_INIT(&fileConfig, WDF_NO_EVENT_CALLBACK, WDF_NO_EVENT_CALLBACK, netuio_evt_file_cleanup);
    WdfDeviceInitSetFileObjectConfig(DeviceInit, &fileConfig, &fileAttributes);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, NETUIO_CONTEXT_DATA);
    WdfDeviceInitSetIoInCallerContextCallback(DeviceInit, netuio_evt_IO_in_caller_context);

    status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);

    if (NT_SUCCESS(status)) {
        // Create a device interface so that applications can find and talk to us.
        status = WdfDeviceCreateDeviceInterface(device, &GUID_DEVINTERFACE_netUIO, NULL);
    }

    if (NT_SUCCESS(status)) {
        // Retrieve and store PCI information
        status = get_pci_device_info(device);
    }

    if (NT_SUCCESS(status)) {
        // Create a symbolic link name for user-space access
        status = create_device_specific_symbolic_link(device);
    }

    if (NT_SUCCESS(status)) {
        // Initialize the I/O Package and any Queues
        status = netuio_queue_initialize(device);
    }

    return status;
}

_Use_decl_annotations_
NTSTATUS
netuio_map_hw_resources(WDFDEVICE Device, WDFCMRESLIST Resources, WDFCMRESLIST ResourcesTranslated)
{
    UNREFERENCED_PARAMETER(Resources);

    NTSTATUS status;

    PNETUIO_CONTEXT_DATA  ctx;
    ctx = netuio_get_context_data(Device);

    if (!ctx) {
        return STATUS_UNSUCCESSFUL;
    }

    PCI_COMMON_HEADER pci_config = {0};
    ULONG bytes_returned;

    // Read PCI configuration space
    bytes_returned = ctx->bus_interface.GetBusData(
        ctx->bus_interface.Context,
        PCI_WHICHSPACE_CONFIG,
        &pci_config,
        0,
        sizeof(pci_config));

    if (bytes_returned != sizeof(pci_config)) {
        status = STATUS_NOT_SUPPORTED;
        goto end;
    }

    // Device type is implictly enforced by .inf
    ASSERT(PCI_CONFIGURATION_TYPE(&pci_config) == PCI_DEVICE_TYPE);

    PCM_PARTIAL_RESOURCE_DESCRIPTOR descriptor;
    ULONG next_descriptor = 0;
    ULONGLONG bar_addr = 0;
    ULONG curr_bar = 0;
    ULONG prev_bar = 0;

    for (INT bar_index = 0; bar_index < PCI_MAX_BAR; bar_index++) {
        prev_bar = curr_bar;
        curr_bar = pci_config.u.type0.BaseAddresses[bar_index];
        if (curr_bar == 0 || (prev_bar & PCI_TYPE_64BIT)) {
            // Skip this bar
            ctx->bar[bar_index].base_addr.QuadPart = 0;
            ctx->bar[bar_index].size = 0;
            ctx->bar[bar_index].virt_addr = 0;

            ctx->dpdk_hw[bar_index].mdl = NULL;
            ctx->dpdk_hw[bar_index].mem.size = 0;

            continue;
        }

        // Find next CmResourceTypeMemory
        do {
            descriptor = WdfCmResourceListGetDescriptor(ResourcesTranslated, next_descriptor);
            next_descriptor++;

            if (descriptor == NULL) {
                status = STATUS_DEVICE_CONFIGURATION_ERROR;
                goto end;
            }
        } while (descriptor->Type != CmResourceTypeMemory);

        // Assert that we have the correct descriptor
        ASSERT((descriptor->Flags & CM_RESOURCE_MEMORY_BAR) != 0);

        if (curr_bar & PCI_TYPE_64BIT) {
            ASSERT(bar_index != PCI_TYPE0_ADDRESSES - 1);
            bar_addr = ((ULONGLONG)pci_config.u.type0.BaseAddresses[bar_index + 1] << 32) | (curr_bar & PCI_ADDRESS_MEMORY_ADDRESS_MASK);
        }
        else
        {
            bar_addr = curr_bar & PCI_ADDRESS_MEMORY_ADDRESS_MASK;
        }

        ASSERT((ULONGLONG)descriptor->u.Memory.Start.QuadPart == bar_addr);

        // Retrieve and map the BARs
        ctx->bar[bar_index].base_addr.QuadPart = descriptor->u.Memory.Start.QuadPart;
        ctx->bar[bar_index].size = descriptor->u.Memory.Length;
        ctx->bar[bar_index].virt_addr = MmMapIoSpace(descriptor->u.Memory.Start,
                                                     descriptor->u.Memory.Length,
                                                     MmNonCached);
        if (ctx->bar[bar_index].virt_addr == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        // Allocate an MDL for the device BAR, so we can map it to the user's process context later.
        ctx->dpdk_hw[bar_index].mdl = IoAllocateMdl(ctx->bar[bar_index].virt_addr,
                                                    (ULONG)ctx->bar[bar_index].size,
                                                    FALSE,
                                                    FALSE,
                                                    NULL);
        if (!ctx->dpdk_hw[bar_index].mdl) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        ctx->dpdk_hw[bar_index].mem.size = ctx->bar[bar_index].size;
    } // for bar_index

    status = STATUS_SUCCESS;

end:
    if (status != STATUS_SUCCESS) {
        netuio_free_hw_resources(Device);
    }

    return status;
}

_Use_decl_annotations_
VOID
netuio_free_hw_resources(WDFDEVICE Device)
{
    PNETUIO_CONTEXT_DATA  ctx;
    ctx = netuio_get_context_data(Device);

    if (ctx) {
        for (UINT8 bar_index = 0; bar_index < PCI_MAX_BAR; bar_index++) {

            // Free the allocated MDLs
            if (ctx->dpdk_hw[bar_index].mdl) {
                IoFreeMdl(ctx->dpdk_hw[bar_index].mdl);
            }

            // Unmap all the BAR regions previously mapped
            if (ctx->bar[bar_index].virt_addr) {
                MmUnmapIoSpace(ctx->bar[bar_index].virt_addr, ctx->bar[bar_index].size);
            }
        }

        RtlZeroMemory(ctx->dpdk_hw, sizeof(ctx->dpdk_hw));
        RtlZeroMemory(ctx->bar, sizeof(ctx->bar));
    }
}


