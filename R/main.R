source("processing_functions.R")
library(xlsx)
library(stringr)
library(dplyr)
library(pracma)
library(ggplot2)
library(scales)
library(fpp)
library(ggstatsplot)

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
calculate_and_write_overall_stats <- function(files_with_offsets, output_path)
{
  # Create output in the master output dir
  output_file <- file.path(output_path, "overall_stats.csv")

  headers <- c("Device", "Intervals", "Outlier Intervals (Frames)", 
      "Frame Mean", "Frame SD", "Frame CoV",
      "TxFrame Mean", "TxFrame SD", "TxFrame CoV",
      "RxFrame Mean", "RxFrame SD", "RxFrame CoV",
      "Outlier Intervals (Bytes)", "Byte Mean", "Byte SD", "Byte CoV",
      "TxByte Mean", "TxByte SD", "TxByte CoV",
      "RxByte Mean", "RxByte SD", "RxByte CoV")
  
  # Process the list of files
  for (i in seq_along(files_with_offsets))
  {
    filepath <- files_with_offsets[[i]][[1]]
    start_offset <- files_with_offsets[[i]][[2]]
    
    overall_stats <- generate_overall_stats(filepath)

    if(!is.list(overall_stats))
    {
      warning(paste("No data found in file: ", basename(filepath)))
      next
    }
    
    if(i == 1)
    {
      dataframe <- data.frame(overall_stats)
      colnames(dataframe) <- headers
    }
    else
    {
      dataframe[nrow(dataframe) + 1,] = overall_stats
    }
  }
  
  write.csv(dataframe, output_file, row.names=FALSE)
}

create_and_write_plots <- function(files_with_offsets, output_path)
{
  # Create plot dirs
  base_plot_path <- file.path(output_path, "plots")
  packet_plot_path <- file.path(output_path, "packet_plots")
  byte_plot_path <- file.path(output_path, "byte_plots")
  dir.create(packet_plot_path, showWarnings=FALSE)
  dir.create(byte_plot_path, showWarnings=FALSE)
  
  # Process the list of files
  for (i in seq_along(files_with_offsets))
  {
    filepath <- files_with_offsets[[i]][[1]]

    plots <- generate_plots(filepath)
    
    # Frame plots
    plot_names <- names(plots[["frameplots"]])
    for (j in seq_along(plots[["frameplots"]]))
    {
      plot_name <- plot_names[[j]]
      outfile_name <- paste(plot_name, ".png", sep="")
      suppressMessages(ggsave(file.path(packet_plot_path,outfile_name), plot=plots[["frameplots"]][[j]]))
    }
    
    # Byte plots
    plot_names <- names(plots[["byteplots"]])
    for (j in seq_along(plots[["byteplots"]]))
    {
      plot_name <- plot_names[[j]]
      outfile_name <- paste(plot_name, ".png", sep="")
      suppressMessages(ggsave(file.path(byte_plot_path,outfile_name), plot=plots[["byteplots"]][[j]]))
    }
  }
}

# Main processing function
process_and_write_data <- function(directory_path, output_path)
{
  # Get paths and offsets for all files in the directory
  files_with_offsets <- get_files_with_start_offsets(directory_path)
  
  # Create results dir
  dir.create(output_path, showWarnings=FALSE)
  
  # Process data
  calculate_and_write_overall_stats(files_with_offsets, output_path)
  create_and_write_plots(files_with_offsets, output_path)
}

# Get location of this script
script_dir <- getwd()
input_dir <- file.path(script_dir, "datasets/FullThirtyMinutes")
output_dir <- file.path(script_dir, "output")

process_and_write_data(input_dir, output_dir)
