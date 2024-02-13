remove_outliers <- function(dataset, column_name)
{
  data_mean <- mean(dataset[[column_name]])
  three_sigma <- 3 * sd(dataset[[column_name]])
  lower_bound <- data_mean - three_sigma
  upper_bound <- data_mean + three_sigma
  
  no_outlier_dataframe <- dataset[dataset[[column_name]] >= lower_bound & dataset[[column_name]] <= upper_bound,]
  return(no_outlier_dataframe)
}

generate_overall_stats_for_column <- function(dataset, column_name, sliding_window_size)
{
  ret_list <- list()
  
  # Use rolling mean to generate statistics
  rolling_mean_data <- rollmean(dataset[[column_name]], k=sliding_window_size, fill=NA, align='right')
  
  # Compute field names
  base_field_name <- tolower((gsub(" ", "", column_name)))
  mean_field_name <- paste(base_field_name, "mean", sep=".")
  sd_field_name <- paste(base_field_name, "sd", sep=".")
  cov_field_name <- paste(base_field_name, "cov", sep=".")
  
  # Only process if we have non-0 data
  if(any(rolling_mean_data > 0, na.rm=TRUE))
  {
    rolling_mean <- mean(rolling_mean_data,na.rm=TRUE)
    rolling_sd <- sd(rolling_mean_data,na.rm=TRUE)
    rolling_CoV <- rolling_sd/rolling_mean
    ret_list[[mean_field_name]] <- rolling_mean
    ret_list[[sd_field_name]] <- rolling_sd
    ret_list[[cov_field_name]] <- rolling_CoV
  }
  else
  {
    ret_list[[mean_field_name]] <- 0
    ret_list[[sd_field_name]] <- NA
    ret_list[[cov_field_name]] <- NA
  }
  
  return(ret_list)
}

generate_overall_stats <- function(file_path)
{
  dataset <- read.csv(file_path)
  
  # Verify there's data in the file
  if(nrow(dataset) == 0)
  {
     return(NA)
  }
  
  ret_list <- list() 
  ret_list[["name"]] <- dataset[["Device"]][[1]]
  
  # Start with frames
  frames_no_outliers <- remove_outliers(dataset, "Frames")
  
  # Only process if we have data
  if(any(frames_no_outliers[["Frames"]] > 0))
  {
    # Calculate removed outlier count for frames
    original_count <- nrow(dataset)
    new_count <- nrow(frames_no_outliers)
    removed_count <- original_count - new_count
    ret_list[["elem_count"]] <- new_count
    ret_list[["frames.outliers_removed_count"]] <- removed_count
    
    # Get stats for frame elements
    frame_stats <- generate_overall_stats_for_column(frames_no_outliers, "Frames", 12)
    txframe_stats <- generate_overall_stats_for_column(frames_no_outliers, "TxFrames", 12)
    rxframe_stats <- generate_overall_stats_for_column(frames_no_outliers, "RxFrames", 12)
    ret_list <- c(ret_list, frame_stats, txframe_stats, rxframe_stats)
  }
  else
  {
    ret_list <- c(ret_list, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA)
  }
  
  # Now do bytes
  bytes_no_outliers <- remove_outliers(dataset, "Bytes")
  
  # Only process if we have data
  if(any(frames_no_outliers[["Bytes"]] > 0))
  {
    # Calculate removed outlier count for bytes
    original_count <- nrow(dataset)
    new_count <- nrow(bytes_no_outliers)
    removed_count <- original_count - new_count
    ret_list[["bytes.outliers_removed_count"]] <- removed_count
    
    # Get stats for byte elements
    byte_stats <- generate_overall_stats_for_column(bytes_no_outliers, "Bytes", 12)
    txbyte_stats <- generate_overall_stats_for_column(bytes_no_outliers, "TxBytes", 12)
    rxbyte_stats <- generate_overall_stats_for_column(bytes_no_outliers, "RxBytes", 12)
    ret_list <- c(ret_list, byte_stats, txbyte_stats, rxbyte_stats)
  }
  else
  {
    ret_list <- c(ret_list, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA)
  }
  
  return(ret_list)
}

generate_plots <- function(file_path)
{
  dataset <- read.csv(file_path)
  
  # Verify there's data in the file
  if(nrow(dataset) == 0)
  {
     return(NA)
  }
 
  plot_list <- list()
  frame_plot_list <- list()
  byte_plot_list <- list()
  
  device_name <- gsub(" ", "", dataset[["Device"]][[1]])
   
  # Plots generated are:
  # - Original Frames (black) with outlier removed rolling mean (red)
  plot_name <- paste(device_name, "-Packets", sep="")
  plot <- plot_data_over_time(dataset, "Frames", 12)
  frame_plot_list[[plot_name]] <- plot
  
  # - Original TxFrames (black) with outlier removed rolling mean (red)
  plot_name <- paste(device_name, "-TxPackets", sep="")
  plot <- plot_data_over_time(dataset, "TxFrames", 12)
  frame_plot_list[[plot_name]] <- plot
  
  # - Original RxFrames (black) with outlier removed rolling mean (red)
  plot_name <- paste(device_name, "-RxPackets", sep="")
  plot <- plot_data_over_time(dataset, "RxFrames", 12)
  frame_plot_list[[plot_name]] <- plot
  
  # - Original Bytes (black) with outlier removed rolling mean (red)
  plot_name <- paste(device_name, "-Bytes", sep="")
  plot <- plot_data_over_time(dataset, "Bytes", 12)
  byte_plot_list[[plot_name]] <- plot
  
  # - Original Bytes (black) with outlier removed rolling mean (red)
  plot_name <- paste(device_name, "-TxBytes", sep="")
  plot <- plot_data_over_time(dataset, "TxBytes", 12)
  byte_plot_list[[plot_name]] <- plot
  
  # - Original Bytes (black) with outlier removed rolling mean (red)
  plot_name <- paste(device_name, "-RxBytes", sep="")
  plot <- plot_data_over_time(dataset, "RxBytes", 12)
  byte_plot_list[[plot_name]] <- plot
  
  plot_list[["frameplots"]] <- frame_plot_list
  plot_list[["byteplots"]] <- byte_plot_list

  return(plot_list)
}

plot_data_over_time <- function(dataset, column_name, sliding_window_size)
{
  dataframe <- data.frame(dataset)
  
  # Overall
  data <- dataset[[column_name]]
  
  if(length(data) > 0)
  {
    no_outlier_dataframe <- remove_outliers(dataset, column_name)
    no_outlier_dataframe <- no_outlier_dataframe %>% mutate(rolling_avg=rollmean(no_outlier_dataframe[[column_name]], k=sliding_window_size, fill=NA, align='right'))
    
    the_plot <- ggplot(data=dataframe, aes(x=StartTime)) + 
      geom_line(aes(y=.data[[column_name]]), color="gray30") +
      geom_line(data=no_outlier_dataframe, aes(y=rolling_avg), color="darkred", linetype="solid") +
      scale_y_continuous(expand=c(0,0), limits=c(0,(max(dataframe[[column_name]]) * 1.05))) +
      scale_x_continuous(expand=c(0,0), breaks = scales::breaks_width(3600 * 6), labels = function(x) format(x / 3600)) +
      xlab("Capture Time (Hours)") +
      ylab(paste(column_name,"(Total)"))
  
    return(the_plot)
  }
  else
  {
    warning(paste("WARNING: No observations to plot for", basename(file_path)))
  }
}