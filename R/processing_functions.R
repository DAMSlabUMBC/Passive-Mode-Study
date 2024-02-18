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
  daily_mean_field_name <- paste(base_field_name, "daily_mean", sep=".")
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
    ret_list[[daily_mean_field_name]] <- rolling_mean * 48
  }
  else
  {
    ret_list[[mean_field_name]] <- 0
    ret_list[[sd_field_name]] <- NA
    ret_list[[cov_field_name]] <- NA
    ret_list[[daily_mean_field_name]] <- 0
  }
  
  return(ret_list)
}

generate_overall_stats <- function(file_path, type="")
{
  dataset <- read.csv(file_path)
  
  # Verify there's data in the file
  if(nrow(dataset) == 0)
  {
     return(NA)
  }
  
  frame_col_name <- "Frames"
  txframe_col_name <- "TxFrames"
  rxframe_col_name <- "RxFrames"
  byte_col_name <- "Bytes"
  txbyte_col_name <- "TxBytes"
  rxbyte_col_name <- "RxBytes"
  
  if(type == "LAN")
  {
    frame_col_name <- "LanFrames"
    txframe_col_name <- "LanTxFrames"
    rxframe_col_name <- "LanRxFrames"
    byte_col_name <- "LanBytes"
    txbyte_col_name <- "LanTxBytes"
    rxbyte_col_name <- "LanRxBytes"
  }
  else if(type == "WAN")
  {
    frame_col_name <- "WanFrames"
    txframe_col_name <- "WanTxFrames"
    rxframe_col_name <- "WanRxFrames"
    byte_col_name <- "WanBytes"
    txbyte_col_name <- "WanTxBytes"
    rxbyte_col_name <- "WanRxBytes"
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
    frame_stats <- generate_overall_stats_for_column(frames_no_outliers, frame_col_name, 12)
    txframe_stats <- generate_overall_stats_for_column(frames_no_outliers, txframe_col_name, 12)
    rxframe_stats <- generate_overall_stats_for_column(frames_no_outliers, rxframe_col_name, 12)
    ret_list <- c(ret_list, frame_stats, txframe_stats, rxframe_stats)
  }
  else
  {
    ret_list <- c(ret_list, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA)
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
    byte_stats <- generate_overall_stats_for_column(bytes_no_outliers, byte_col_name, 12)
    txbyte_stats <- generate_overall_stats_for_column(bytes_no_outliers, txbyte_col_name, 12)
    rxbyte_stats <- generate_overall_stats_for_column(bytes_no_outliers, rxbyte_col_name, 12)
    ret_list <- c(ret_list, byte_stats, txbyte_stats, rxbyte_stats)
  }
  else
  {
    ret_list <- c(ret_list, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA)
  }
  
  return(ret_list)
}

generate_lan_wan_stats <- function(full_filepath)
{
  dataset <- read.csv(full_filepath)
  
  # Verify there's data in the file
  if(nrow(dataset) == 0)
  {
    return(NA)
  }
  
  ret_list <- list() 
  ret_list[["device"]] <- dataset[["Device"]][[1]]
  
  # Start with frames
  # Remove outliers from the main dataset
  frames_no_outliers <- remove_outliers(dataset, "Frames")
  
  # Only process if we have data
  if(any(frames_no_outliers[["Frames"]] > 0))
  {
    full_frame_count <- sum(frames_no_outliers$Frames)
    lan_tx_frame_count <- sum(frames_no_outliers$LanTxFrames)
    lan_rx_frame_count <- sum(frames_no_outliers$LanRxFrames)
    wan_tx_frame_count <- sum(frames_no_outliers$WanTxFrames)
    wan_rx_frame_count <- sum(frames_no_outliers$WanRxFrames)
    
    if(lan_tx_frame_count + wan_tx_frame_count + lan_rx_frame_count + wan_rx_frame_count  != full_frame_count)
    {
      print(full_filepath)
      warning(paste("Mismatched frame count in file ", full_filepath))
    }
    
    ret_list[["lan_tx_frame_pct"]] <- lan_tx_frame_count / full_frame_count
    ret_list[["lan_rx_frame_pct"]] <- lan_rx_frame_count / full_frame_count
    ret_list[["wan_tx_frame_pct"]] <- wan_tx_frame_count / full_frame_count
    ret_list[["wan_rx_frame_pct"]] <- wan_rx_frame_count / full_frame_count
  }
  else
  {
    ret_list[["lan_tx_frame_pct"]] <- NA
    ret_list[["lan_rx_frame_pct"]] <- NA
    ret_list[["wan_tx_frame_pct"]] <- NA
    ret_list[["wan_rx_frame_pct"]] <- NA
  }
  
  # Now do bytes
  # Remove outliers from the main dataset
  bytes_no_outliers <- remove_outliers(dataset, "Bytes")
  
  # Only process if we have data
  if(any(bytes_no_outliers[["Bytes"]] > 0))
  {
    full_bytes_count <- sum(bytes_no_outliers$Bytes)
    lan_tx_bytes_count <- sum(bytes_no_outliers$LanTxBytes)
    lan_rx_bytes_count <- sum(bytes_no_outliers$LanRxBytes)
    wan_tx_bytes_count <- sum(bytes_no_outliers$WanTxBytes)
    wan_rx_bytes_count <- sum(bytes_no_outliers$WanRxBytes)
    
    if(lan_tx_bytes_count + wan_tx_bytes_count + lan_rx_bytes_count + wan_rx_bytes_count  != full_bytes_count)
    {
      warning(paste("Mismatched bytes count in file ", full_filepath))
    }
    
    ret_list[["lan_tx_bytes_pct"]] <- lan_tx_bytes_count / full_bytes_count
    ret_list[["lan_rx_bytes_pct"]] <- lan_rx_bytes_count / full_bytes_count
    ret_list[["wan_tx_bytes_pct"]] <- wan_tx_bytes_count / full_bytes_count
    ret_list[["wan_rx_bytes_pct"]] <- wan_rx_bytes_count / full_bytes_count
  }
  else
  {
    ret_list[["lan_tx_bytes_pct"]] <- NA
    ret_list[["lan_rx_bytes_pct"]] <- NA
    ret_list[["wan_tx_bytes_pct"]] <- NA
    ret_list[["wan_rx_bytes_pct"]] <- NA
  }
  
  return(ret_list)
}

generate_plots <- function(file_path, type="")
{
  dataset <- read.csv(file_path)
  
  # Verify there's data in the file
  if(nrow(dataset) == 0)
  {
     return(NA)
  }
  
  frame_col_name <- "Frames"
  txframe_col_name <- "TxFrames"
  rxframe_col_name <- "RxFrames"
  byte_col_name <- "Bytes"
  txbyte_col_name <- "TxBytes"
  rxbyte_col_name <- "RxBytes"
  
  if(type == "LAN")
  {
    frame_col_name <- "LanFrames"
    txframe_col_name <- "LanTxFrames"
    rxframe_col_name <- "LanRxFrames"
    byte_col_name <- "LanBytes"
    txbyte_col_name <- "LanTxBytes"
    rxbyte_col_name <- "LanRxBytes"
  }
  else if(type == "WAN")
  {
    frame_col_name <- "WanFrames"
    txframe_col_name <- "WanTxFrames"
    rxframe_col_name <- "WanRxFrames"
    byte_col_name <- "WanBytes"
    txbyte_col_name <- "WanTxBytes"
    rxbyte_col_name <- "WanRxBytes"
  }
 
  plot_list <- list()
  frame_plot_list <- list()
  byte_plot_list <- list()
  
  device_name <- gsub(" ", "", dataset[["Device"]][[1]])
   
  # Plots generated are:
  # - Original Frames (black) with outlier removed rolling mean (red)
  plot_name <- paste(device_name, "-Packets", sep="")
  plot <- plot_data_over_time(dataset, "Frames", frame_col_name, 12)
  frame_plot_list[[plot_name]] <- plot
  
  # - Original TxFrames (black) with outlier removed rolling mean (red)
  plot_name <- paste(device_name, "-TxPackets", sep="")
  plot <- plot_data_over_time(dataset, "Frames", txframe_col_name, 12)
  frame_plot_list[[plot_name]] <- plot
  
  # - Original RxFrames (black) with outlier removed rolling mean (red)
  plot_name <- paste(device_name, "-RxPackets", sep="")
  plot <- plot_data_over_time(dataset, "Frames", rxframe_col_name, 12)
  frame_plot_list[[plot_name]] <- plot
  
  # - Original Bytes (black) with outlier removed rolling mean (red)
  plot_name <- paste(device_name, "-Bytes", sep="")
  plot <- plot_data_over_time(dataset, "Bytes", byte_col_name, 12)
  byte_plot_list[[plot_name]] <- plot
  
  # - Original Bytes (black) with outlier removed rolling mean (red)
  plot_name <- paste(device_name, "-TxBytes", sep="")
  plot <- plot_data_over_time(dataset, "Bytes", txbyte_col_name, 12)
  byte_plot_list[[plot_name]] <- plot
  
  # - Original Bytes (black) with outlier removed rolling mean (red)
  plot_name <- paste(device_name, "-RxBytes", sep="")
  plot <- plot_data_over_time(dataset, "Bytes", rxbyte_col_name, 12)
  byte_plot_list[[plot_name]] <- plot
  
  plot_list[["frameplots"]] <- frame_plot_list
  plot_list[["byteplots"]] <- byte_plot_list

  return(plot_list)
}

plot_data_over_time <- function(dataset, outlier_filter_column, column_name, sliding_window_size)
{
  dataframe <- data.frame(dataset)
  
  # Overall
  data <- dataset[[column_name]]
  
  
  if(length(data) > 0)
  {
    no_outlier_dataframe <- remove_outliers(dataset, outlier_filter_column)
    no_outlier_dataframe <- no_outlier_dataframe %>% mutate(rolling_avg=rollmean(no_outlier_dataframe[[column_name]], k=sliding_window_size, fill=NA, align='right'))
    no_outlier_dataframe <- na.omit(no_outlier_dataframe)
    
    the_plot <- ggplot(data=dataframe, aes(x=StartTime)) + 
      geom_line(aes(y=.data[[column_name]]), color="gray30") +
      
      # We suppress messages here since the rolling mean doesn't start until X value of 11 which causes warnings
      suppressMessages(geom_line(data=no_outlier_dataframe, aes(y=rolling_avg), color="darkred", linetype="solid")) +
      
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