# Smart Home IoT Passive Mode Analysis

## Installing Requirements
The files in this repository were designed to run on a current Linux operating system. The following are required to run the full pipeline:
* Python >= 3.11 (https://www.python.org/)
* Tshark >= 4.2.6 (https://tshark.dev/)

Once the above are acquired, the rest of the requirements can be installed using the requirements.txt file within the python directory of the repository. It is recommended to create a virtual environment with `python -m venv /path/to/env` becore installing python dependencies. 

After creating and activating the virtual environment, install the dependencies within the requirements file using:

`pip install -r requirements.txt`

## Architecture
![Workflow diagram](Workflow.png)

## Datasets
A list of datasets is given in the [Dataset File](datasets.csv), currently this contains a single dataset used within the paper _Your Smart Home Exchanged 3M Messages: Defining and Analyzing Smart Device Passive Mode_. If you have a dataset you wish to add to this project, please follow the instructions in [Contributing to the Datasets](#contributing).

## Example Guide Setup
For each section below, example commands are provided for running with the dataset from _Your Smart Home Exchanged 3M Messages: Defining and Analyzing Smart Device Passive Mode_. To setup your environment to follow along with these steps, download the first dataset [datasets.csv](datasets.csv). Then, ensure your directory tree matches the following:

    └── ~/PercomArtifact
        ├── Passive-Mode-Study/ (this repo)
        ├── Percom116Dataset/ (the unzipped dataset)
        ├── Workspace/ (a working directory for storing results)
    


## Processing and Splitting PCAPs

## <a name="contributing"></a> Contributing to the Datasets
