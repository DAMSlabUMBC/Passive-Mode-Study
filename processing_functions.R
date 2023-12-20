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
  window_2 <- dataset[[column_name]][seq(from=2, to=length(dataset[[column_name]]), by=4)]
  window_3 <- dataset[[column_name]][seq(from=3, to=length(dataset[[column_name]]), by=4)]
  window_4 <- dataset[[column_name]][seq(from=4, to=length(dataset[[column_name]]), by=4)]
  
  window_1_mean <- mean(window_1)
  window_1_sd <- sd(window_1)
  window_1_CoV <- window_1_sd/window_1_mean
  ret_list[["window_1.mean"]] <- window_1_mean
  ret_list[["window_1.sd"]] <- window_1_sd
  ret_list[["window_1.cov"]] <- window_1_CoV
  
  window_2_mean <- mean(window_2)
  window_2_sd <- sd(window_2)
  window_2_CoV <- window_2_sd/window_2_mean
  ret_list[["window_2.mean"]] <- window_2_mean
  ret_list[["window_2.sd"]] <- window_2_sd
  ret_list[["window_2.cov"]] <- window_2_CoV
  
  window_3_mean <- mean(window_3)
  window_3_sd <- sd(window_3)
  window_3_CoV <- window_3_sd/window_3_mean
  ret_list[["window_3.mean"]] <- window_3_mean
  ret_list[["window_3.sd"]] <- window_3_sd
  ret_list[["window_3.cov"]] <- window_3_CoV
  
  window_4_mean <- mean(window_4)
  window_4_sd <- sd(window_4)
  window_4_CoV <- window_4_sd/window_4_mean
  ret_list[["window_4.mean"]] <- window_4_mean
  ret_list[["window_4.sd"]] <- window_4_sd
  ret_list[["window_4.cov"]] <- window_4_CoV
  
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