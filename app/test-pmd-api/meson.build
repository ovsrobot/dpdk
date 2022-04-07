# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

# override default name to drop the hyphen
name = 'testpmd-api'
cflags += [
    '-Wno-deprecated-declarations'
]
sources += files(
    'main.c',
    'api_impl.cc'
)

ldflags += [
    '-ldl',
    '-lgrpc++_reflection',
]

ext_deps += [protobuf_dep, grpc_dep, grpcpp_dep, dependency('threads')]

if dpdk_conf.has('RTE_HAS_JANSSON')
    ext_deps += jansson_dep
endif

deps += ['ethdev', 'cmdline', 'bus_pci']
if dpdk_conf.has('RTE_CRYPTO_SCHEDULER')
    deps += 'crypto_scheduler'
endif
if dpdk_conf.has('RTE_LIB_BITRATESTATS')
    deps += 'bitratestats'
endif
if dpdk_conf.has('RTE_LIB_BPF')
    deps += 'bpf'
endif
if dpdk_conf.has('RTE_LIB_GRO')
    deps += 'gro'
endif
if dpdk_conf.has('RTE_LIB_GSO')
    deps += 'gso'
endif
if dpdk_conf.has('RTE_LIB_LATENCYSTATS')
    deps += 'latencystats'
endif
if dpdk_conf.has('RTE_LIB_METRICS')
    deps += 'metrics'
endif
if dpdk_conf.has('RTE_LIB_PDUMP')
    deps += 'pdump'
endif
if dpdk_conf.has('RTE_NET_BOND')
    deps += 'net_bond'
endif
if dpdk_conf.has('RTE_NET_BNXT')
    deps += 'net_bnxt'
endif
if dpdk_conf.has('RTE_NET_I40E')
    deps += 'net_i40e'
endif
if dpdk_conf.has('RTE_NET_IXGBE')
    deps += 'net_ixgbe'
endif
if dpdk_conf.has('RTE_NET_DPAA')
    deps += ['bus_dpaa', 'mempool_dpaa', 'net_dpaa']
endif

if meson.version().version_compare('>=0.55')
    grpc_cpp_plugin_path = grpc_cpp_plugin.full_path()
    grpc_python_plugin_path = grpc_python_plugin.full_path()
else
    grpc_cpp_plugin_path = grpc_cpp_plugin.path()
    grpc_python_plugin_path = grpc_python_plugin.path()
endif


cpp_generator = generator(protoc, 
                output    : ['@BASENAME@.pb.cc', '@BASENAME@.pb.h', '@BASENAME@.grpc.pb.cc', '@BASENAME@.grpc.pb.h'],
                arguments : [
                    '--proto_path=@CURRENT_SOURCE_DIR@',
                    '--plugin=protoc-gen-grpc=@0@'.format(grpc_cpp_plugin_path), 
                    '--cpp_out=@BUILD_DIR@',
                    '--grpc_out=@BUILD_DIR@',
                    '@INPUT@'
                ])

python_generator = generator(protoc, 
                output    : ['@BASENAME@_pb2.py', '@BASENAME@_pb2_grpc.py'],
                arguments : [
                    '--proto_path=@CURRENT_SOURCE_DIR@',
                    '--plugin=protoc-gen-grpc=@0@'.format(grpc_python_plugin_path), 
                    '--python_out=@BUILD_DIR@',
                    '--grpc_out=@BUILD_DIR@',
                    '@INPUT@'
                ])

sources += cpp_generator.process('api.proto')
sources += python_generator.process('api.proto')