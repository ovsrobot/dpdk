#! /usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Intel Corporation

"""
Script to automate running crypto performance tests for a range of test
cases and devices as configured in the JSON file.
The results are processed and output into various graphs in PDF files.
Currently, throughput and latency tests are supported.
"""

import glob
import json
import os
import shutil
import subprocess
from argparse import ArgumentParser
from datetime import datetime
import img2pdf
import pandas as pd
import plotly.express as px

SCRIPT_PATH = os.path.dirname(__file__) + "/"
GRAPHS_PATH = SCRIPT_PATH + "graph_crypto_perf_graphs/"
PDFS_PATH = SCRIPT_PATH + "graph_crypto_perf_pdfs/"


class Grapher:
    """Grapher object containing all graphing functions. """
    def __init__(self, dev):
        self.graph_num = 0
        self.dev = dev
        self.test = ""
        self.ptest = ""
        self.data = pd.DataFrame()
        if not os.path.exists(GRAPHS_PATH):
            os.makedirs(GRAPHS_PATH)

    def save_graph(self, fig):
        """
        Update figure layout to increase readability, output to JPG file.
        """
        fig.update_layout(font_size=30, title_x=0.5, title_font={"size": 30},
                          margin=dict(t=200, l=150, r=150, b=150))
        fig.write_image(GRAPHS_PATH + "%s_%d.jpg" % (self.dev,
                                                     self.graph_num))

    def boxplot_graph(self, x_axis_label):
        """Plot a boxplot graph for the given parameters."""
        fig = px.box(self.data, x=x_axis_label,
                     title="Device: " + self.dev + "<br>" + self.test +
                     "<br>(Outliers Included)", height=1200, width=2400)
        self.save_graph(fig)
        self.graph_num += 1

    def grouped_graph(self, y_axis_label, x_axis_label, color_label):
        """Plot a grouped barchart using the given parameters."""
        if (self.data[y_axis_label] == 0).all():
            return
        fig = px.bar(self.data, x=x_axis_label, color=color_label,
                     y=y_axis_label,
                     title="Device: " + self.dev + "<br>" + self.test + "<br>"
                     + y_axis_label + " for each " + x_axis_label +
                     "/" + color_label,
                     barmode="group",
                     height=1200,
                     width=2400)
        fig.update_xaxes(type='category')
        self.save_graph(fig)
        self.graph_num += 1

    def histogram_graph(self, x_axis_label):
        """Plot a histogram graph using the given parameters."""
        quart1 = self.data[x_axis_label].quantile(0.25)
        quart3 = self.data[x_axis_label].quantile(0.75)
        inter_quart_range = quart3 - quart1
        dev_data_out = self.data[~((self.data[x_axis_label] <
                                    (quart1 - 1.5 * inter_quart_range)) |
                                   (self.data[x_axis_label] >
                                    (quart3 + 1.5 * inter_quart_range)))]
        fig = px.histogram(dev_data_out, x=x_axis_label,
                           title="Device: " + self.dev + "<br>" + self.test +
                           "<br>(Outliers removed using Interquartile Range)",
                           height=1200,
                           width=2400)
        max_val = dev_data_out[x_axis_label].max()
        min_val = dev_data_out[x_axis_label].min()
        fig.update_traces(xbins=dict(
            start=min_val,
            end=max_val,
            size=(max_val - min_val) / 200
        ))
        self.save_graph(fig)
        self.graph_num += 1


def cleanup_throughput_datatypes(data):
    """Cleanup data types of throughput test results dataframe. """
    data['burst_size'] = data['burst_size'].astype('int')
    data['buffer_size(b)'] = data['buffer_size(b)'].astype('int')
    data['burst_size'] = data['burst_size'].astype('category')
    data['buffer_size(b)'] = data['buffer_size(b)'].astype('category')
    data['failed_enq'] = data['failed_enq'].astype('int')
    data['throughput(gbps)'] = data['throughput(gbps)'].astype('float')
    data['ops(millions)'] = data['ops(millions)'].astype('float')
    data['cycles_per_buf'] = data['cycles_per_buf'].astype('float')
    return data


def process_test_results(grapher, data):
    """
    Process results from the test case,
    calling graph functions to output graph images.
    """
    print("\tProcessing Test Case Results: " + grapher.test)
    if grapher.ptest == "throughput":
        grapher.data = cleanup_throughput_datatypes(data)
        for y_label in ["throughput(gbps)", "ops(millions)",
                        "cycles_per_buf", "failed_enq"]:
            grapher.grouped_graph(y_label, "buffer_size(b)",
                                  "burst_size")
    elif grapher.ptest == "latency":
        data['time(us)'] = data['time(us)'].astype('float')
        grapher.data = data
        grapher.histogram_graph("time(us)")
        grapher.boxplot_graph("time(us)")
    else:
        print("Invalid ptest")
        return


def create_results_pdf(dev):
    """Output results graphs to one PDF."""
    if not os.path.exists(PDFS_PATH):
        os.makedirs(PDFS_PATH)
    dev_graphs = sorted(glob.glob(GRAPHS_PATH + "%s_*.jpg" % dev), key=(
        lambda x: int((x.rsplit('_', 1)[1]).split('.')[0])))
    if dev_graphs:
        with open(PDFS_PATH + "/%s_results.pdf" % dev, "wb") as pdf_file:
            pdf_file.write(img2pdf.convert(dev_graphs))


def run_test(test_cmd, test, grapher, timestamp, params):
    """Run performance test app for the given test case parameters."""
    print("\n\tRunning Test Case: " + test)
    try:
        process_out = subprocess.check_output([test_cmd] + params,
                                              universal_newlines=True,
                                              stderr=subprocess.STDOUT)
        rows = []
        for line in process_out.split('\n'):
            if not line:
                continue
            if line.startswith('#'):
                columns = line[1:].split(',')
            elif line[0].isdigit():
                rows.append(line.split(','))
            else:
                continue
        data = pd.DataFrame(rows, columns=columns)
        data['date'] = timestamp
        grapher.test = test
        process_test_results(grapher, data)
    except subprocess.CalledProcessError as err:
        print("\tCannot run performance test application for: " + str(err))
        return


def run_test_suite(test_cmd, dut, test_cases, timestamp):
    """Parse test cases for the test suite and run each test."""
    print("\nRunning Test Suite: " + dut)
    default_params = []
    grapher = Grapher(dut)
    for (key, val) in test_cases['default']['eal'].items():
        if len(key) == 1:
            default_params.append("-" + key + " " + val)
        else:
            default_params.append("--" + key + "=" + val)

    default_params.append("--")
    for (key, val) in test_cases['default']['app'].items():
        if isinstance(val, bool):
            default_params.append("--" + key if val is True else "")
        else:
            default_params.append("--" + key + "=" + val)

    if 'ptest' not in test_cases['default']['app']:
        print("Test Suite must contain default ptest value, skipping")
        return
    grapher.ptest = test_cases['default']['app']['ptest']

    for (test, params) in {k: v for (k, v) in test_cases.items() if
                           k != "default"}.items():
        extra_params = []
        for (key, val) in params.items():
            extra_params.append("--" + key + "=" + val)
        run_test(test_cmd, test, grapher, timestamp,
                 default_params + extra_params)

    create_results_pdf(dut)


def parse_args():
    """Parse command-line arguments passed to script."""
    parser = ArgumentParser()
    parser.add_argument('-f', '--file-path',
                        default=shutil.which('dpdk-test-crypto-perf'),
                        help="Path for test perf app")
    parser.add_argument('-t', '--test-suites', nargs='+', default=["all"],
                        help="List of device test suites to run")
    args = parser.parse_args()
    return args.file_path, args.test_suites


def main():
    """
    Load JSON config and call relevant functions to run chosen test suites.
    """
    test_cmd, test_suites = parse_args()
    if not os.path.isfile(test_cmd):
        print("Invalid filepath!")
        return
    try:
        with open(SCRIPT_PATH + 'graph_crypto_perf_config.json') as conf:
            test_suite_options = json.load(conf)
    except json.decoder.JSONDecodeError as err:
        print("Error loading JSON config: " + err.msg)
        return
    timestamp = pd.Timestamp(datetime.now())

    if test_suites != ["all"]:
        dev_list = []
        for (dut, test_cases) in {k: v for (k, v) in test_suite_options.items()
                                  if k in test_suites}.items():
            dev_list.append(dut)
            run_test_suite(test_cmd, dut, test_cases, timestamp)
        if not dev_list:
            print("No valid device test suites chosen!")
            return
    else:
        for (dut, test_cases) in test_suite_options.items():
            run_test_suite(test_cmd, dut, test_cases, timestamp)

    if os.path.exists(GRAPHS_PATH):
        shutil.rmtree(GRAPHS_PATH)


if __name__ == "__main__":
    main()
