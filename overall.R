source("processing_functions.R")
library(xlsx)

dir.create(file.path(".", "output"), showWarnings=FALSE)

headers <- c("Device", "Overall Mean", "Overall SD", "Overall CoV", "Window 1 Mean", "Window 1 SD", "Window 1 CoV", "Window 2 Mean", "Window 2 SD", "Window 2 CoV", "Window 3 Mean", "Window 3 SD", "Window 3 CoV", "Window 4 Mean", "Window 4 SD", "Window 4 CoV", "Day Mean", "Day SD", "Day SoV")

data <- read_aligned_six_hour_split_packets("datasets/US1-EchoDot5-aligned-Nov2-Nov8-stats.csv", "Echo Dot 5th Gen", 6)
dataframe_packets <- data.frame(data)
colnames(dataframe_packets) <- headers

#data <- read_aligned_six_hour_split_packets("datasets/output-44_3D_54_BE_12_3C-aligned-and-21600-split-NO-UPDATE.csv", "Echo Dot 5th Gen (No Update)", 6)
#dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/US1-Govee-aligned-Nov2-Nov8-stats.csv", "Govee", 6)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

#data <- read_aligned_six_hour_split_packets("datasets/output-60_74_F4_1B_24_16-aligned-and-21600-split-NO-UPDATE.csv", "Govee (No Update)", 6)
#dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/US1-AmazonLight-aligned-Nov2-Nov8-stats.csv", "Amazon Light", 6)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/US1-Netvue-aligned-Nov2-Nov8-stats.csv", "Netvue", 6)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/US1-Litokam-aligned-Nov2-Nov8-stats.csv", "Litokam", 6)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/US1-TPLink-aligned-Nov2-Nov8-stats.csv", "TP-Link HS110 (US)", 6)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/US1-PhilipsBridge-aligned-Nov2-Nov8-stats.csv", "Philips Hue Bridge (US)", 6)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/US1-MetaquestPro-aligned-Nov23-Nov27-stats.csv", "Meta Quest Pro", 4)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/EU-PhilipsBridge-aligned-Nov24h18-Nov28h12-stats.csv", "Philips Hue Bridge (EU)", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/EU-TPLink-aligned-Nov24h18-Nov28h12-stats.csv", "TP-Link HS110 (EU)", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/EU-EchoDot3-aligned-Nov24h18-Nov28h12-stats.csv", "Echo Dot 3th Gen", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/EU-NestMini-aligned-Nov24h18-Nov28h12-stats.csv", "Google Nest Mini", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/EU-NestThermostat-aligned-Nov24h18-Nov28h12-stats.csv", "Google Nest Learning Thermostat", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/EU-GoogleSpeaker-aligned-Nov24h18-Nov28h12-stats.csv", "Google Home Assistant Speaker", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/EU-EchoShow5-aligned-Nov24h18-Nov28h12-stats.csv", "Amazon Echo Show 5th Gen", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/EU-NestCamera-aligned-Nov24h18-Nov28h12-stats.csv", "Google Nest Camera 1st Gen", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/EU-TPLinkLight-aligned-Nov24h18-Nov28h12-stats.csv", "TP-Link Smart Bulb", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/EU-MaxcioStrip-aligned-Nov24h18-Nov28h12-stats.csv", "Maxcio Smart Strip", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/EU-SonyTV-aligned-Nov24h18-Nov28h12-stats.csv", "Sony KD-43XH8096", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/EU-DLinkStrip-aligned-Nov24h18-Nov28h12-stats.csv", "D-Link DCS-8300LH-30B0", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/US2-MagicLeap-aligned-Oct24-Oct27-stats.csv", "Magic Leap 1", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/US2-HoloLens-aligned-Oct24-Oct27-stats.csv", "HoloLens 2", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/US2-MetaQuest1-aligned-Oct24-Oct27-stats.csv", "Meta Quest 1", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/US2-MetaQuest2-aligned-Oct24-Oct27-stats.csv", "Meta Quest 2", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/US2-Dreamglass-aligned-Oct24-Oct27-stats.csv", "DreamGlass Air", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/US2-RoboRock-aligned-Nov10-Nov15-stats.csv", "RoboRock", 6)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

write.xlsx(dataframe_packets, file="output/overall.xlsx", sheetName="Packets", row.names=FALSE)



data <- read_aligned_six_hour_split_bytes("datasets/US1-EchoDot5-aligned-Nov2-Nov8-stats.csv", "Echo Dot 5th Gen", 6)
dataframe_bytes <- data.frame(data)
colnames(dataframe_bytes) <- headers

#data <- read_aligned_six_hour_split_bytes("datasets/output-44_3D_54_BE_12_3C-aligned-and-21600-split-NO-UPDATE.csv", "Echo Dot 5th Gen (No Update)", 6)
#dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/US1-Govee-aligned-Nov2-Nov8-stats.csv", "Govee", 6)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

#data <- read_aligned_six_hour_split_bytes("datasets/output-60_74_F4_1B_24_16-aligned-and-21600-split-NO-UPDATE.csv", "Govee (No Update)", 6)
#dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/US1-AmazonLight-aligned-Nov2-Nov8-stats.csv", "Amazon Light", 6)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/US1-Netvue-aligned-Nov2-Nov8-stats.csv", "Netvue", 6)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/US1-Litokam-aligned-Nov2-Nov8-stats.csv", "Litokam", 6)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/US1-TPLink-aligned-Nov2-Nov8-stats.csv", "TP-Link HS110 (US)", 6)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/US1-PhilipsBridge-aligned-Nov2-Nov8-stats.csv", "Philips Hue Bridge (US)", 6)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/US1-MetaquestPro-aligned-Nov23-Nov27-stats.csv", "Meta Quest Pro", 4)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/EU-PhilipsBridge-aligned-Nov24h18-Nov28h12-stats.csv", "Philips Hue Bridge (EU)", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/EU-TPLink-aligned-Nov24h18-Nov28h12-stats.csv", "TP-Link HS110 (EU)", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/EU-EchoDot3-aligned-Nov24h18-Nov28h12-stats.csv", "Echo Dot 3th Gen", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/EU-NestMini-aligned-Nov24h18-Nov28h12-stats.csv", "Google Nest Mini", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/EU-NestThermostat-aligned-Nov24h18-Nov28h12-stats.csv", "Google Nest Learning Thermostat", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/EU-GoogleSpeaker-aligned-Nov24h18-Nov28h12-stats.csv", "Google Home Assistant Speaker", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/EU-EchoShow5-aligned-Nov24h18-Nov28h12-stats.csv", "Amazon Echo Show 5th Gen", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/EU-NestCamera-aligned-Nov24h18-Nov28h12-stats.csv", "Google Nest Camera 1st Gen", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/EU-TPLinkLight-aligned-Nov24h18-Nov28h12-stats.csv", "TP-Link Smart Bulb", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/EU-MaxcioStrip-aligned-Nov24h18-Nov28h12-stats.csv", "Maxcio Smart Strip", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/EU-SonyTV-aligned-Nov24h18-Nov28h12-stats.csv", "Sony KD-43XH8096", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/EU-DLinkStrip-aligned-Nov24h18-Nov28h12-stats.csv", "D-Link DCS-8300LH-30B0", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/US2-MagicLeap-aligned-Oct24-Oct27-stats.csv", "Magic Leap 1", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/US2-HoloLens-aligned-Oct24-Oct27-stats.csv", "HoloLens 2", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/US2-MetaQuest1-aligned-Oct24-Oct27-stats.csv", "Meta Quest 1", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/US2-MetaQuest2-aligned-Oct24-Oct27-stats.csv", "Meta Quest 2", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/US2-Dreamglass-aligned-Oct24-Oct27-stats.csv", "DreamGlass Air", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/US2-RoboRock-aligned-Nov10-Nov15-stats.csv", "RoboRock", 6)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

write.xlsx(dataframe_bytes, file="output/overall.xlsx", sheetName="Bytes", row.names=FALSE, append=TRUE)
