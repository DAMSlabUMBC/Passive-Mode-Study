source("processing_functions.R")
library(xlsx)
library(stringr)
library(dplyr)
library(pracma)
library(ggplot2)
library(scales)
library(fpp)
library(ggstatsplot)

# Calculates overall, six hour split, and day split CoVs for the devices
calculate_and_write_overall_stats <- function(file_list, output_path)
{
  # Create output in the master output dir
  full_output_file <- file.path(output_path, "overall_stats.csv")
  lan_output_file <- file.path(output_path, "overall_stats_LAN.csv")
  wan_output_file <- file.path(output_path, "overall_stats_WAN.csv")

  headers <- c("Device", "Intervals", "Outlier Intervals (Frames)", 
      "Frame Mean", "Frame SD", "Frame CoV", "Daily Frame Mean",
      "TxFrame Mean", "TxFrame SD", "TxFrame CoV", "Daily TxFrame Mean",
      "RxFrame Mean", "RxFrame SD", "RxFrame CoV", "Daily RxFrame Mean",
      "Outlier Intervals (Bytes)", "Byte Mean", "Byte SD", "Byte CoV", "Daily Byte Mean",
      "TxByte Mean", "TxByte SD", "TxByte CoV", "Daily TxByte Mean",
      "RxByte Mean", "RxByte SD", "RxByte CoV", "Daily RxByte Mean")
  
  # Process the list of files
  for (i in seq_along(file_list))
  {
    full_filepath <- file_list[[i]]
    
    full_overall_stats <- generate_overall_stats(full_filepath)
    lan_overall_stats <- generate_overall_stats(full_filepath, "LAN")
    wan_overall_stats <- generate_overall_stats(full_filepath, "WAN")

    # Full
    if(!is.list(full_overall_stats))
    {
      warning(paste("No data found in file: ", basename(full_filepath)))
      next
    }
    
    if(i == 1)
    {
      full_dataframe <- data.frame(full_overall_stats)
      colnames(full_dataframe) <- headers
    }
    else
    {
      full_dataframe[nrow(full_dataframe) + 1,] = full_overall_stats
    }
    
    # LAN
    if(!is.list(lan_overall_stats))
    {
      warning(paste("No data found in file: ", basename(lan_filepath)))
      next
    }
    
    if(i == 1)
    {
      lan_dataframe <- data.frame(lan_overall_stats)
      colnames(lan_dataframe) <- headers
    }
    else
    {
      lan_dataframe[nrow(lan_dataframe) + 1,] = lan_overall_stats
    }
    
    # WAN
    if(!is.list(wan_overall_stats))
    {
      warning(paste("No data found in file: ", basename(wan_filepath)))
      next
    }
    
    if(i == 1)
    {
      wan_dataframe <- data.frame(wan_overall_stats)
      colnames(wan_dataframe) <- headers
    }
    else
    {
      wan_dataframe[nrow(wan_dataframe) + 1,] = wan_overall_stats
    }
  }
  
  write.csv(full_dataframe, full_output_file, row.names=FALSE)
  write.csv(lan_dataframe, lan_output_file, row.names=FALSE)
  write.csv(wan_dataframe, wan_output_file, row.names=FALSE)
}

# Calculates overall, six hour split, and day split CoVs for the devices
calculate_lan_wan_stats <- function(file_list, output_path)
{
  # Create output in the master output dir
  full_output_file <- file.path(output_path, "LAN_WAN_stats.csv")
  
  headers <- c("Device", "Lan TxPacket Percent", "Lan RxPacket Percent", 
               "Wan TxPacket Percent", "Wan RxPacket Percent", 
               "Lan TxByte Percent", "Lan RxByte Percent", 
               "Wan TxByte Percent", "Wan RxByte Percent")
               
  # Process the list of files
  for (i in seq_along(file_list))
  {
    full_filepath <- file_list[[i]]
    
    stats <- generate_lan_wan_stats(full_filepath)

    if(i == 1)
    {
      dataframe <- data.frame(stats)
      colnames(dataframe) <- headers
    }
    else
    {
      dataframe[nrow(dataframe) + 1,] = stats
    }
  }
  
  write.csv(dataframe, full_output_file, row.names=FALSE)
}


create_and_write_plots <- function(file_list, output_path, type="")
{
  # Create plot dirs
  packet_plot_path <- file.path(output_path, "packet_plots")
  byte_plot_path <- file.path(output_path, "byte_plots")
  dir.create(packet_plot_path, showWarnings=FALSE)
  dir.create(byte_plot_path, showWarnings=FALSE)
  
  # Process the list of files
  for (filepath in file_list)
  {
    plots <- generate_plots(filepath, type)
    
    # Verify the files acutally contained data
    if(!any(is.na(plots)))
    {
      # Frame plots
      plot_names <- names(plots[["frameplots"]])
      for (i in seq_along(plots[["frameplots"]]))
      {
        plot_name <- plot_names[[i]]
        outfile_name <- paste(plot_name, ".png", sep="")
        suppressMessages(ggsave(file.path(packet_plot_path,outfile_name), plot=plots[["frameplots"]][[i]]))
      }
      
      # Byte plots
      plot_names <- names(plots[["byteplots"]])
      for (i in seq_along(plots[["byteplots"]]))
      {
        plot_name <- plot_names[[i]]
        outfile_name <- paste(plot_name, ".png", sep="")
        suppressMessages(ggsave(file.path(byte_plot_path,outfile_name), plot=plots[["byteplots"]][[i]]))
      }
    }
  }
}

# Main processing function
process_and_write_data <- function(full_path, output_path, generate_plots)
{
  # Get file list
 file_list <- list.files(path = full_path, pattern = "*.csv", full.names = T)
  
  # Create results dirs
  full_output_path <- file.path(output_path, "Full")
  lan_output_path <- file.path(output_path, "LAN")
  wan_output_path <- file.path(output_path, "WAN")
  dir.create(output_path, showWarnings=FALSE)
  dir.create(full_output_path, showWarnings=FALSE)
  dir.create(lan_output_path, showWarnings=FALSE)
  dir.create(wan_output_path, showWarnings=FALSE)
  
  # Process data
  print("Processing overall stats")
  calculate_and_write_overall_stats(file_list, output_path)
  
  print("Processing LAN vs WAN stats")
  calculate_lan_wan_stats(file_list, output_path)
  
  if(generate_plots)
  {
    # Generate graphs
    print("Generating full plots")
    create_and_write_plots(file_list, full_output_path)
    print("Generating LAN plots")
    create_and_write_plots(file_list, lan_output_path, "LAN")
    print("Generating WAN plots")
    create_and_write_plots(file_list, wan_output_path, "WAN")
  }
}

# Get location of this script
script_dir <- getwd()
full_input_dir <- file.path(script_dir, "datasets")
output_dir <- file.path(script_dir, "output")

process_and_write_data(full_input_dir, output_dir, FALSE)
