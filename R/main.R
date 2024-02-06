source("processing_functions.R")
library(xlsx)
library(stringr)
library(dplyr)

# Gets stat files in directory as a list of vectors in the form (file_path, start_offset)
get_files_with_start_offsets <- function(directory_path)
{
  file_list <- list.files(path = directory_path, pattern = "*.csv", full.names = T)
  
  ret_list <- list()
  
  for (i in seq_along(file_list))
  {
    filepath <- file_list[[i]]
    filename <- basename(filepath)
    
    # File offsets are all aligned by 6 hours windows. In order to properly align the output file
    # we need to say what hour the files starts on. To do this, we use the following convention:
    # 0 = 00:00
    # 1 = 06:00
    # 2 = 12:00
    # 3 = 18:00
    start_offset <- 0
    
    # Since we loop through arbitrary files, to find the offset, we assume the file name contains
    # "h##" if the offset isn't 0. We also assume the first instance of this in the file name is
    # the proper offset
    name_tokens <- strsplit(filename, split="-")
    parsed_offsets <- str_extract(name_tokens[[1]], regex("h(06|1[268])"))
    
    # Offset exists if true
    if(!all(is.na(parsed_offsets)))
    {
      offset_indicies <- which(!is.na(parsed_offsets))
      start_offset_index <- min(offset_indicies)
      offset_text <- parsed_offsets[[start_offset_index]]
      
      start_offset <- case_when(
        offset_text == "h06" ~ 1,
        offset_text == "h12" ~ 2,
        offset_text == "h18" ~ 3
      )
    }
    
    file_vec <- c(filepath, start_offset)
    ret_list[[length(ret_list) + 1]] = file_vec
  }
  
  return(ret_list)
}

# Calculates overall, six hour split, and day split CoVs for the devices
calculate_and_write_cov <- function(files_with_offsets, output_path)
{
  # Create output in the master output dir
  cov_output_file <- file.path(output_path, "CoVs.xlsx")

  headers <- c("File", "Overall CoV", "00:00-06:00 CoV", "00:00-06:00 CoV", "00:00-06:00 CoV", "00:00-06:00 CoV", "Day CoV")
  
  # Process the list of files
  for (i in seq_along(files_with_offsets))
  {
    filepath <- files_with_offsets[[i]][[1]]
    start_offset <- files_with_offsets[[i]][[2]]
    
    # Now that we know the offsets, start processing data
    packet_data <- compute_aligned_cov(filepath, start_offset, "Frames")
    bytes_data <- compute_aligned_cov(filepath, start_offset, "Bytes")
    
    if(i == 1)
    {
      packets_dataframe <- data.frame(packet_data)
      bytes_dataframe <- data.frame(bytes_data)
      colnames(packets_dataframe) <- headers
      colnames(bytes_dataframe) <- headers
    }
    else
    {
      packets_dataframe[nrow(packets_dataframe) + 1,] = packet_data
      bytes_dataframe[nrow(bytes_dataframe) + 1,] = bytes_data
    }
  }
  
  write.xlsx(packets_dataframe, file=cov_output_file, sheetName="Packets", row.names=FALSE)
  write.xlsx(bytes_dataframe, file=cov_output_file, sheetName="Bytes", row.names=FALSE, append=TRUE)
}

# Main processing function
process_and_write_data <- function(directory_path, output_path)
{
  # Get paths and offsets for all files in the directory
  files_with_offset <- get_files_with_start_offsets(directory_path)
  
  # Create results dir
  dir.create(output_path, showWarnings=FALSE)
  
  # CoV for devices
  calculate_and_write_cov(files_with_offset, output_path)
}

# Get location of this script
script_dir <- dirname(sys.frame(1)$ofile)
input_dir <- file.path(script_dir, "datasets/Per-Device")
output_dir <- file.path(script_dir, "output")

process_and_write_data(input_dir, output_dir)
