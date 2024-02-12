remove_outliers <- function(dataset, column_name)
{
  data_mean <- mean(dataset[[column_name]])
  three_sigma <- 3 * sd(dataset[[column_name]])
  lower_bound <- data_mean - three_sigma
  upper_bound <- data_mean + three_sigma
  
  no_outlier_dataframe <- dataset[dataset[[column_name]] >= lower_bound & dataset[[column_name]] <= upper_bound,]
  return(no_outlier_dataframe)
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

calculate_number_of_outliers <- function(file_path, column_name)
{
  dataset <- read.csv(file_path)
  
  # Remove outliers
  
  no_outlier_dataframe <- remove_outliers(dataset, column_name)
  
  original <- nrow(dataset)
  new <- nrow(no_outlier_dataframe)
  removed <- original - new
  
  if(removed > 0)
  {
    print(paste(basename(file_path), "Removed:", removed, " elements which is", (removed / original) * 100, "% of the elements"))
    print(paste("Mean:", mean(no_outlier_dataframe[[column_name]]), "SD:", sd(no_outlier_dataframe[[column_name]])))
  }
  else
  {
    print(paste(basename(file_path), "Removed no elements"))
    print(paste("Mean:", mean(no_outlier_dataframe[[column_name]]), "SD:", sd(no_outlier_dataframe[[column_name]])))
  }
}

compute_cov <- function(file_path, column_name)
{
  dataset <- read.csv(file_path)
  ret_list <- list() 
  ret_list[["file"]] <- basename(file_path)
  
  # Remove outliers
  no_outlier_dataframe <- remove_outliers(dataset, column_name)
  
  # Overall
  overall_mean <- mean(no_outlier_dataframe[[column_name]])
  overall_sd <- sd(no_outlier_dataframe[[column_name]])
  overall_CoV <- overall_sd/overall_mean
  ret_list[["overall.cov"]] <- overall_CoV
  
  rolling_mean_data <- rollmean(dataset[[column_name]], k=12, fill=NA, align='right')
  print(paste(basename(file_path), column_name))
  print(mean(rolling_mean_data,na.rm=TRUE))
  
  rolling_mean <- mean(rolling_mean_data,na.rm=TRUE)
  rolling_sd <- sd(rolling_mean_data,na.rm=TRUE)
  rolling_CoV <- rolling_sd/rolling_mean
  ret_list[["rolling_mean.cov"]] <- rolling_CoV
  
  rolling_mean_data <- rollmean(no_outlier_dataframe[[column_name]], k=12, fill=NA, align='right')
  
  rolling_mean <- mean(rolling_mean_data,na.rm=TRUE)
  rolling_sd <- sd(rolling_mean_data,na.rm=TRUE)
  rolling_CoV <- rolling_sd/rolling_mean
  ret_list[["rolling_mean_outlier.cov"]] <- rolling_CoV

  return(ret_list)
}


plot_data_over_time <- function(file_path, column_name, observations_per_hour, output_dir)
{
  library(ggplot2)
  
  dataset <- read.csv(file_path)
  dataframe <- data.frame(dataset)
  
  # Overall
  data <- dataset[[column_name]]
  
  if(length(data) > 0)
  {
    time_series <- ts(data, start=0, frequency=observations_per_hour)
    
    dataframe <- dataframe %>% mutate(rolling_avg=rollmean(dataframe[[column_name]], k=12, fill=NA, align='right'))
    
    no_outlier_dataframe <- remove_outliers(dataset, column_name)
    
    no_outlier_dataframe <- no_outlier_dataframe %>% mutate(rolling_avg=rollmean(no_outlier_dataframe[[column_name]], k=12, fill=NA, align='right'))
    
    rolling_avg_mean = mean(no_outlier_dataframe$rolling_avg,na.rm=TRUE)
    rolling_avg_sd = sd(no_outlier_dataframe$rolling_avg,na.rm=TRUE)
    
    outname <- paste(basename(file_path),".png",sep="")
    the_plot <- ggplot(data=no_outlier_dataframe, aes(x=StartTime)) + 
      geom_line(data=dataframe, aes(y=.data[[column_name]]), color="black") +
      geom_line(aes(y=rolling_avg), color="darkred", linetype="solid") +
      scale_y_continuous(expand=c(0,0), limits=c(0,(max(dataframe[[column_name]]) * 1.05))) +
      scale_x_continuous(expand=c(0,0), breaks = scales::breaks_width(3600 * 6), labels = function(x) format(x / 3600)) +
      ggtitle(basename(file_path)) +
      xlab("Capture Time (Hours)") +
      ylab(paste(column_name,"(Total)"))
  
    suppressMessages(ggsave(file.path(output_dir,outname), plot=the_plot))
  }
  else
  {
    print(paste("WARNING: No observations for", basename(file_path)))
  }
}