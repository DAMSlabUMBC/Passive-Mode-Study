# Existing sankey libraries weren't working with our python environment
# Here we just copy the sankey generation libraries from 
# Anneya Golob & marcomanz & pierre-sassoulas & jorwoods & vgalisson
# into this file.
#
# The code to actually configure what gets generated as at the bottom
# of this file in generate_sankey()


# -*- coding: utf-8 -*-
r"""
Produces simple Sankey Diagrams with matplotlib.
@author: Anneya Golob & marcomanz & pierre-sassoulas & jorwoods & vgalisson
                      .-.
                 .--.(   ).--.
      <-.  .-.-.(.->          )_  .--.
       `-`(     )-'             `)    )
         (o  o  )                `)`-'
        (      )                ,)
        ( ()  )                 )
         `---"\    ,    ,    ,/`
               `--' `--' `--'
                |  |   |   |
                |  |   |   |
                '  |   '   |
"""

# fmt: off
import logging
from collections import defaultdict

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
# fmt: on

LOGGER = logging.getLogger(__name__)


class PySankeyException(Exception):
    """ Generic PySankey Exception. """


class NullsInFrame(PySankeyException):
    pass


class LabelMismatch(PySankeyException):
    pass


def check_data_matches_labels(labels, data, side):
    """Check wether or not data matches labels.

    Raise a LabelMismatch Exception if not."""
    if len(labels) > 0:
        if isinstance(data, list):
            data = set(data)
        if isinstance(data, pd.Series):
            data = set(data.unique().tolist())
        if isinstance(labels, list):
            labels = set(labels)
        if labels != data:
            msg = "\n"
            if len(labels) <= 20:
                msg = "Labels: " + ",".join(labels) + "\n"
            if len(data) < 20:
                msg += "Data: " + ",".join(data)
            raise LabelMismatch(
                "{0} labels and data do not match.{1}".format(side, msg)
            )


def sankey(
        left,
        right,
        leftWeight=None,
        rightWeight=None,
        colorDict=None,
        leftLabels=None,
        rightLabels=None,
        aspect=4,
        rightColor=False,
        fontsize=14,
        ax=None
):
    """
    Make Sankey Diagram showing flow from left-->right

    Inputs:
        left = NumPy array of object labels on the left of the diagram
        right = NumPy array of corresponding labels on the right of the diagram
            len(right) == len(left)
        leftWeight = NumPy array of weights for each strip starting from the
            left of the diagram, if not specified 1 is assigned
        rightWeight = NumPy array of weights for each strip starting from the
            right of the diagram, if not specified the corresponding leftWeight
            is assigned
        colorDict = Dictionary of colors to use for each label
            {'label':'color'}
        leftLabels = order of the left labels in the diagram
        rightLabels = order of the right labels in the diagram
        aspect = vertical extent of the diagram in units of horizontal extent
        rightColor = If true, each strip in the diagram will be be colored
                    according to its left label
        ax = optional, matplotlib axes to plot on, otherwise uses current axes.
    Ouput:
        ax : matplotlib Axes
    """
    if aspect <= 0:
        raise ValueError("Aspect must be strictly superior to 0 (default is 4).")

    if ax is None:
        ax = plt.gca()

    if leftWeight is None:
        leftWeight = []
    if rightWeight is None:
        rightWeight = []
    if leftLabels is None:
        leftLabels = []
    if rightLabels is None:
        rightLabels = []
    # Check weights
    if len(leftWeight) == 0:
        leftWeight = np.ones(len(left))

    if len(rightWeight) == 0:
        rightWeight = leftWeight

    # Create Dataframe
    if isinstance(left, pd.Series):
        left = left.reset_index(drop=True)
    if isinstance(right, pd.Series):
        right = right.reset_index(drop=True)
    dataFrame = pd.DataFrame(
        {
            "left": left,
            "right": right,
            "leftWeight": leftWeight,
            "rightWeight": rightWeight,
        },
        index=range(len(left))
    )

    if len(dataFrame[(dataFrame.left.isnull()) | (dataFrame.right.isnull())]):
        raise NullsInFrame("Sankey graph does not support null values.")

    # Identify all labels that appear 'left' or 'right'
    allLabels = pd.Series(
        np.r_[dataFrame.left.unique(), dataFrame.right.unique()]
    ).unique()
    LOGGER.debug("Labels to handle : %s", allLabels)

    # Identify left labels
    if len(leftLabels) == 0:
        leftLabels = pd.Series(dataFrame.left.unique()).unique()
    else:
        check_data_matches_labels(leftLabels, dataFrame["left"], "left")

    # Identify right labels
    if len(rightLabels) == 0:
        rightLabels = pd.Series(dataFrame.right.unique()).unique()
    else:
        check_data_matches_labels(rightLabels, dataFrame["right"], "right")

    # If no colorDict given, make one
    if colorDict is None:
        colorDict = {}
        palette = "hls"
        colorPalette = sns.color_palette(palette, len(allLabels))
        for i, label in enumerate(allLabels):
            colorDict[label] = colorPalette[i]
    else:
        missing = [label for label in allLabels if label not in colorDict.keys()]
        if missing:
            msg = (
                "The colorDict parameter is missing values for the following labels : "
            )
            msg += "{}".format(", ".join(missing))
            raise ValueError(msg)
    LOGGER.debug("The colordict value are : %s", colorDict)

    # Determine widths of individual strips
    ns_l = defaultdict()
    ns_r = defaultdict()
    for leftLabel in leftLabels:
        leftDict = {}
        rightDict = {}
        for rightLabel in rightLabels:
            leftDict[rightLabel] = dataFrame[
                (dataFrame.left == leftLabel) & (dataFrame.right == rightLabel)
            ].leftWeight.sum()
            rightDict[rightLabel] = dataFrame[
                (dataFrame.left == leftLabel) & (dataFrame.right == rightLabel)
            ].rightWeight.sum()
        ns_l[leftLabel] = leftDict
        ns_r[leftLabel] = rightDict

    # Determine positions of left label patches and total widths
    leftWidths, topEdge = _get_positions_and_total_widths(
        dataFrame, leftLabels, 'left', aspect)

    # Determine positions of right label patches and total widths
    rightWidths, topEdge = _get_positions_and_total_widths(
        dataFrame, rightLabels, 'right', aspect)

    # Total vertical extent of diagram
    xMax = topEdge / aspect

    # Draw vertical bars on left and right of each  label's section & print label
    for leftLabel in leftLabels:
        ax.fill_between(
            [-0.02 * xMax, 0],
            2 * [leftWidths[leftLabel]["bottom"]],
            2 * [leftWidths[leftLabel]["bottom"] + leftWidths[leftLabel]["left"]],
            color=colorDict[leftLabel],
            alpha=0.99,
        )
        ax.text(
            -0.05 * xMax,
            leftWidths[leftLabel]["bottom"] + 0.5 * leftWidths[leftLabel]["left"],
            leftLabel,
            {"ha": "right", "va": "center"},
            fontsize=fontsize,
        )
    for rightLabel in rightLabels:
        ax.fill_between(
            [xMax, 1.02 * xMax],
            2 * [rightWidths[rightLabel]["bottom"]],
            2 * [rightWidths[rightLabel]["bottom"] + rightWidths[rightLabel]["right"]],
            color=colorDict[rightLabel],
            alpha=0.99,
        )
        ax.text(
            1.05 * xMax,
            rightWidths[rightLabel]["bottom"] + 0.5 * rightWidths[rightLabel]["right"],
            rightLabel,
            {"ha": "left", "va": "center"},
            fontsize=fontsize,
        )

    # Plot strips
    for leftLabel in leftLabels:
        for rightLabel in rightLabels:
            labelColor = leftLabel
            if rightColor:
                labelColor = rightLabel
            if (
                len(
                    dataFrame[
                        (dataFrame.left == leftLabel) & (dataFrame.right == rightLabel)
                    ]
                )
                > 0
            ):
                # Create array of y values for each strip, half at left value,
                # half at right, convolve
                ys_d = np.array(
                    50 * [leftWidths[leftLabel]["bottom"]]
                    + 50 * [rightWidths[rightLabel]["bottom"]]
                )
                ys_d = np.convolve(ys_d, 0.05 * np.ones(20), mode="valid")
                ys_d = np.convolve(ys_d, 0.05 * np.ones(20), mode="valid")
                ys_u = np.array(
                    50 * [leftWidths[leftLabel]["bottom"] + ns_l[leftLabel][rightLabel]]
                    + 50
                    * [rightWidths[rightLabel]["bottom"] + ns_r[leftLabel][rightLabel]]
                )
                ys_u = np.convolve(ys_u, 0.05 * np.ones(20), mode="valid")
                ys_u = np.convolve(ys_u, 0.05 * np.ones(20), mode="valid")

                # Update bottom edges at each label so next strip starts at the right place
                leftWidths[leftLabel]["bottom"] += ns_l[leftLabel][rightLabel]
                rightWidths[rightLabel]["bottom"] += ns_r[leftLabel][rightLabel]
                ax.fill_between(
                    np.linspace(0, xMax, len(ys_d)),
                    ys_d,
                    ys_u,
                    alpha=0.65,
                    color=colorDict[labelColor],
                )
    ax.axis("off")

    return ax


def _get_positions_and_total_widths(df, labels, side, aspect):
    """ Determine positions of label patches and total widths"""
    widths = defaultdict()
    for i, label in enumerate(labels):
        labelWidths = {}
        labelWidths[side] = df[df[side] == label][side + "Weight"].sum()
        if i == 0:
            labelWidths["bottom"] = 0
            labelWidths["top"] = labelWidths[side]
        else:
            bottomWidth = widths[labels[i - 1]]["top"]
            weightedSum = aspect / 200 * df[side + "Weight"].sum()
            labelWidths["bottom"] = bottomWidth + weightedSum
            labelWidths["top"] = labelWidths["bottom"] + labelWidths[side]
            topEdge = labelWidths["top"]
        widths[label] = labelWidths
        LOGGER.debug("%s position of '%s' : %s", side, label, labelWidths)

    return widths, topEdge

def generate_endpoint_dist_sankey():

    url = "sankey_endpoint_dist.csv"
    data_field = pd.read_csv(url, sep=",") # reads the csv

    # device name in csv
    device = "Device"
    # location in csv
    location = "Output"
    # total packet to that destination
    packets = "Packets"

    # Create Sankey diagram 
    sankey(
        left = data_field[device], right=data_field[location], 
        leftWeight = data_field[packets], rightWeight=data_field[packets], 
        aspect=6, fontsize=8
    )

    fig = plt.gcf() # Get current figure

    fig.set_size_inches(5, 4.5) # Set size in inches

    fig.set_facecolor("w") # Set the color of the background to white

    fig.savefig("EndpointTypeDistribution" + ".svg", bbox_inches="tight", format="svg", dpi=300) # Save the figure


def generate_protocol_dist_sankey():

    url = "sankey_proto_dist.csv"
    data_field = pd.read_csv(url, sep=",") # reads the csv

    # device name in csv
    device = "ProtoType"
    # location in csv
    location = "EndpointType"
    # total packet to that destination
    packets = "Pct"

    # Create Sankey diagram 
    sankey(
        left = data_field[device], right=data_field[location], 
        leftWeight = data_field[packets], rightWeight=data_field[packets], 
        aspect=25, fontsize=8
    )

    fig = plt.gcf() # Get current figure

    fig.set_size_inches(5, 1.5) # Set size in inches

    fig.set_facecolor("w") # Set the color of the background to white

    fig.savefig("ProtocolTypeDistribution" + ".svg", bbox_inches="tight", format="svg", dpi=300) # Save the figure


def generate_local_dist_sankey():

    url = "sankey_local_endpoint_dist.csv"
    data_field = pd.read_csv(url, sep=",") # reads the csv

    # device name in csv
    device = "SourceDevice"
    # location in csv
    location = "TargetDevice"
    # total packet to that destination
    packets = "PacketsToTargetPct"

    # Create Sankey diagram 
    sankey(
        left = data_field[device], right=data_field[location], 
        leftWeight = data_field[packets], rightWeight=data_field[packets], 
        aspect=20, fontsize=8
    )

    fig = plt.gcf() # Get current figure

    fig.set_size_inches(5, 4) # Set size in inches

    fig.set_facecolor("w") # Set the color of the background to white

    fig.savefig("LocalTrafficDistribution" + ".svg", bbox_inches="tight", format="svg", dpi=300) # Save the figure

if __name__ == "__main__":
   generate_endpoint_dist_sankey()
   generate_protocol_dist_sankey()
   generate_local_dist_sankey()