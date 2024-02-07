read_aligned_six_hour_split_packets <- function(file_name, device_name, num_days)
{
  ret_list <- read_aligned_six_hour_split(file_name, device_name, num_days, 'Frames')
  return(ret_list)
}

read_aligned_six_hour_split_bytes <- function(file_name, device_name, num_days)
{
  ret_list <- read_aligned_six_hour_split(file_name, device_name, num_days, 'Bytes')
  return(ret_list)
}

# File offsets are all aligned by 6 hours windows. In order to properly align the output file
# we need to say what hour the files starts on. To do this, we use the following convention:
# 0 = 00:00
# 1 = 06:00
# 2 = 12:00
# 3 = 18:00
read_aligned_six_hour_split <- function(file_name, device_name, num_days, column_name)
{
  dataset <- read.csv(file_name)
  ret_list <- list() 
  ret_list[["device"]] <- device_name
  
  # Overall
  overall_mean <- mean(dataset[[column_name]])
  overall_sd <- sd(dataset[[column_name]])
  overall_CoV <- overall_sd/overall_mean
  ret_list[["overall.mean"]] <- overall_mean
  ret_list[["overall.sd"]] <- overall_sd
  ret_list[["overall.cov"]] <- overall_CoV
  
  # Per timeslot
  elems_per_day = 4
  window_1 <- dataset[[column_name]][seq(from=1, to=length(dataset[[column_name]]), by=4)]
  six_to_noon <- dataset[[column_name]][seq(from=2, to=length(dataset[[column_name]]), by=4)]
  noon_to_eighteen <- dataset[[column_name]][seq(from=3, to=length(dataset[[column_name]]), by=4)]
  eighteen_to_midnight <- dataset[[column_name]][seq(from=4, to=length(dataset[[column_name]]), by=4)]
  
  window_1_mean <- mean(window_1)
  window_1_sd <- sd(window_1)
  window_1_CoV <- window_1_sd/window_1_mean
  ret_list[["window_1.mean"]] <- window_1_mean
  ret_list[["window_1.sd"]] <- window_1_sd
  ret_list[["window_1.cov"]] <- window_1_CoV
  
  six_to_noon_mean <- mean(six_to_noon)
  six_to_noon_sd <- sd(six_to_noon)
  six_to_noon_CoV <- six_to_noon_sd/six_to_noon_mean
  ret_list[["six_to_noon.mean"]] <- six_to_noon_mean
  ret_list[["six_to_noon.sd"]] <- six_to_noon_sd
  ret_list[["six_to_noon.cov"]] <- six_to_noon_CoV
  
  noon_to_eighteen_mean <- mean(noon_to_eighteen)
  noon_to_eighteen_sd <- sd(noon_to_eighteen)
  noon_to_eighteen_CoV <- noon_to_eighteen_sd/noon_to_eighteen_mean
  ret_list[["noon_to_eighteen.mean"]] <- noon_to_eighteen_mean
  ret_list[["noon_to_eighteen.sd"]] <- noon_to_eighteen_sd
  ret_list[["noon_to_eighteen.cov"]] <- noon_to_eighteen_CoV
  
  eighteen_to_midnight_mean <- mean(eighteen_to_midnight)
  eighteen_to_midnight_sd <- sd(eighteen_to_midnight)
  eighteen_to_midnight_CoV <- eighteen_to_midnight_sd/eighteen_to_midnight_mean
  ret_list[["eighteen_to_midnight.mean"]] <- eighteen_to_midnight_mean
  ret_list[["eighteen_to_midnight.sd"]] <- eighteen_to_midnight_sd
  ret_list[["eighteen_to_midnight.cov"]] <- eighteen_to_midnight_CoV
  
  # Per day
  day_data <- dataset[[column_name]]
  day_data <- day_data[1:(num_days * elems_per_day)]
  day_data <- split(day_data, rep(1:num_days,each=elems_per_day), drop = TRUE)
  day_sums <- lapply(day_data, sum)
  
  day_mean <- mean(unlist(day_sums))
  day_sd <- sd(unlist(day_sums))
  day_CoV <- day_sd/day_mean
  ret_list[["day.mean"]] <- day_mean
  ret_list[["day.sd"]] <- day_sd
  ret_list[["day.cov"]] <- day_CoV
  
  return(ret_list)
}

# File offsets are all aligned by 6 hours windows. In order to properly align the output file
# we need to say what hour the files starts on. To do this, we use the following convention:
# 0 = 00:00
# 1 = 06:00
# 2 = 12:00
# 3 = 18:00
compute_aligned_cov <- function(file_path, start_hour_enum, column_name)
{
  dataset <- read.csv(file_path)
  ret_list <- list() 
  ret_list[["file"]] <- basename(file_path)
  
  # Overall
  overall_mean <- mean(dataset[[column_name]])
  overall_sd <- sd(dataset[[column_name]])
  overall_CoV <- overall_sd/overall_mean
  ret_list[["overall.cov"]] <- overall_CoV
  
  # Partition data into 4 windows, which captures the same time of day every time 
  # (e.g. window_1 may always contain 00:00-06:00 data)
  elems_per_day = 4
  window_1 <- dataset[[column_name]][seq(from=1, to=length(dataset[[column_name]]), by=elems_per_day)]
  window_2 <- dataset[[column_name]][seq(from=2, to=length(dataset[[column_name]]), by=elems_per_day)]
  window_3 <- dataset[[column_name]][seq(from=3, to=length(dataset[[column_name]]), by=elems_per_day)]
  window_4 <- dataset[[column_name]][seq(from=4, to=length(dataset[[column_name]]), by=elems_per_day)]
  
  # Since the starting time can be different (but is always aligned by 6 hours),
  # we map the windows onto real times based on the start time
  if (start_hour_enum == 0)
  {
    midnight_to_six <- window_1
    six_to_noon <- window_2
    noon_to_eighteen <- window_3
    eighteen_to_midnight <- window_4
  }
  else if (start_hour_enum == 1)
  {
    midnight_to_six <- window_4
    six_to_noon <- window_1
    noon_to_eighteen <- window_2
    eighteen_to_midnight <- window_3
  }
  else if (start_hour_enum == 2)
  {
    midnight_to_six <- window_3
    six_to_noon <- window_4
    noon_to_eighteen <- window_1
    eighteen_to_midnight <- window_2
  }
  else if (start_hour_enum == 3)
  {
    midnight_to_six <- window_2
    six_to_noon <- window_3
    noon_to_eighteen <- window_4
    eighteen_to_midnight <- window_1
  }
  else
  {
    return(NaN)
  }
  
  # Compute CoV across 6 hour blocks
  midnight_to_six_mean <- mean(midnight_to_six)
  midnight_to_six_sd <- sd(midnight_to_six)
  midnight_to_six_CoV <- midnight_to_six_sd/midnight_to_six_mean
  ret_list[["midnight_to_six.cov"]] <- midnight_to_six_CoV
  
  six_to_noon_mean <- mean(six_to_noon)
  six_to_noon_sd <- sd(six_to_noon)
  six_to_noon_CoV <- six_to_noon_sd/six_to_noon_mean
  ret_list[["six_to_noon.cov"]] <- six_to_noon_CoV
  
  noon_to_eighteen_mean <- mean(noon_to_eighteen)
  noon_to_eighteen_sd <- sd(noon_to_eighteen)
  noon_to_eighteen_CoV <- noon_to_eighteen_sd/noon_to_eighteen_mean
  ret_list[["noon_to_eighteen.cov"]] <- noon_to_eighteen_CoV
  
  eighteen_to_midnight_mean <- mean(eighteen_to_midnight)
  eighteen_to_midnight_sd <- sd(eighteen_to_midnight)
  eighteen_to_midnight_CoV <- eighteen_to_midnight_sd/eighteen_to_midnight_mean
  ret_list[["eighteen_to_midnight.cov"]] <- eighteen_to_midnight_CoV
  
  # Computer CoV across days
  num_entries <- length(dataset[[column_name]])
  full_day_count <- num_entries %/% 4
  
  day_data <- dataset[[column_name]]
  day_data <- day_data[1:(full_day_count * elems_per_day)]
  day_data <- split(day_data, rep(1:full_day_count,each=elems_per_day), drop = TRUE)
  day_sums <- lapply(day_data, sum)
  
  day_mean <- mean(unlist(day_sums))
  day_sd <- sd(unlist(day_sums))
  day_CoV <- day_sd/day_mean
  ret_list[["day.cov"]] <- day_CoV
  
  return(ret_list)
}

compute_hurst <- function(file_path, column_name)
{
  library(ggplot2)
  
  dataset <- read.csv(file_path)
  dataframe <- data.frame(dataset)
  ret_list <- list() 
  ret_list[["file"]] <- basename(file_path)
  
  # Overall
  data <- dataset[[column_name]]
  time_series <- ts(data, start=0, frequency=2)
  
  outname <- paste(basename(file_path),".png",sep="")
  
  # For easier display, scale seconds data to be in hours
  #dataframe <- dataframe %>% mutate(StartTime = StartTime / 3600)
  
  #png(filename=file.path("plots",outname))
  the_plot <- ggplot(data=dataframe, aes(x=StartTime, y=Frames)) + 
    geom_line() +
    scale_y_continuous(expand=c(0,0), limits=c(0,(max(dataframe$Frames) * 1.05))) +
    scale_x_continuous(expand=c(0,0), breaks = scales::breaks_width(3600 * 6), labels = function(x) format(x / 3600)) +
    ggtitle("Packets sent over capture timeframe") +
    xlab("Capture Time (Hours)") +
    ylab("Packets (Total)")

  suppressMessages(ggsave(file.path("plots_full",outname), plot=the_plot))
  #invisible(dev.off())
}