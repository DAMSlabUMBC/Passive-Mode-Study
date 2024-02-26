import pandas as pd

# Import the sankey function from the sankey module within pySankey
# pip install pySankey
from pySankey.sankey import sankey
import matplotlib.pyplot as plt

url = "link to csv"
data_field = pd.read_csv(url, sep=",") # reads the csv


# device name in csv
device = ""
# location in csv
location = ""
# total packet to that destination
packets = ""

# Create Sankey diagram 
sankey(
    left = data_field[device], right=data_field[location], 
    leftWeight = data_field[packets], rightWeight=data_field[packets], 
    aspect=20, fontsize=20
)


fig = plt.gcf() # Get current figure


fig.set_size_inches(6, 6) # Set size in inches


fig.set_facecolor("w") # Set the color of the background to white

 
fig.savefig(device + ".png", bbox_inches="tight", dpi=150) # Save the figure
