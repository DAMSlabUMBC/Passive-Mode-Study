source("processing_functions.R")
library(xlsx)

dir.create(file.path(".", "output"), showWarnings=FALSE)

headers <- c("Device", "Overall Mean", "Overall SD", "Overall CoV", "Window 1 Mean", "Window 1 SD", "Window 1 CoV", "Window 2 Mean", "Window 2 SD", "Window 2 CoV", "Window 3 Mean", "Window 3 SD", "Window 3 CoV", "Window 4 Mean", "Window 4 SD", "Window 4 CoV", "Day Mean", "Day SD", "Day SoV")

data <- read_aligned_six_hour_split_packets("datasets/output-44_3D_54_BE_12_3C--aligned-and-21600-split.csv", "Echo Dot 5th Gen", 6)
dataframe_packets <- data.frame(data)
colnames(dataframe_packets) <- headers

data <- read_aligned_six_hour_split_packets("datasets/output-44_3D_54_BE_12_3C-aligned-and-21600-split-NO-UPDATE.csv", "Echo Dot 5th Gen (No Update)", 6)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/output-60_74_F4_1B_24_16--aligned-and-21600-split.csv", "Govee", 6)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/output-60_74_F4_1B_24_16-aligned-and-21600-split-NO-UPDATE.csv", "Govee (No Update)", 6)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/output-64_B7_08_A9_2B_20--aligned-and-21600-split.csv", "Amazon Light", 6)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/output-90_31_4B_71_8E_B6--aligned-and-21600-split.csv", "Netvue", 6)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/output-90_31_4B_71_B2_7B--aligned-and-21600-split.csv", "Litokam", 6)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/output-AC_84_C6_20_FE_4B--aligned-and-21600-split.csv", "TP-Link HS110 (US)", 6)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/output-EC_B5_FA_99_AC_15--aligned-and-21600-split.csv", "Philips Hue Bridge (US)", 6)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/output-EC_B5_FA_80_80_F4--21600-split.csv", "Philips Hue Bridge (EU)", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/output-1C_3B_F3_8D_29_4A--21600-split.csv", "TP-Link HS110 (EU)", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/output-FC_49_2D_34_98_28--21600-split.csv", "Echo Dot 3th Gen", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/output-20_DF_B9_3B_00_90--21600-split.csv", "Google Nest Mini", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/output-64_16_66_BE_44_9C--21600-split.csv", "Google Nest Learning Thermostat", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/output-A4_77_33_DF_C2_4D--21600-split.csv", "Google Home Assistant Speaker", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/output-40_A2_DB_2C_8A_68--21600-split.csv", "Amazon Echo Show 5th Gen", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/output-64_16_66_4A_65_71--21600-split.csv", "Google Nest Camera 1st Gen", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/output-50_C7_BF_5E_A8_48--21600-split.csv", "TP-Link Smart Bulb", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/output-F4_CF_A2_0C_41_F6--21600-split.csv", "Maxcio Smart Strip", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/output-64_FF_0A_88_AF_4A--21600-split.csv", "Sony KD-43XH8096", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/output-B0_C5_54_4A_30_B0--21600-split.csv", "D-Link DCS-8300LH-30B0", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/output-60_4B_AA_01_46_62--21600-split.csv", "Magic Leap 1", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/output-A0_85_FC_2F_7D_A0--21600-split.csv", "HoloLens 2", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/output-2C_26_17_56_C7_22--21600-split.csv", "Meta Quest 1", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/output-80_F3_EF_F7_F7_C1--21600-split.csv", "Meta Quest 2", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/output-C0_84_7D_2E_9C_86--21600-split.csv", "DreamGlass Air", 2)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

data <- read_aligned_six_hour_split_packets("datasets/output-B0_4A_39_24_BB_A6--21600-split.csv", "RoboRock", 6)
dataframe_packets[nrow(dataframe_packets) + 1,] = data

write.xlsx(dataframe_packets, file="output/test.xlsx", sheetName="Packets", row.names=FALSE)



data <- read_aligned_six_hour_split_bytes("datasets/output-44_3D_54_BE_12_3C--aligned-and-21600-split.csv", "Echo Dot 5th Gen", 6)
dataframe_bytes <- data.frame(data)
colnames(dataframe_bytes) <- headers

data <- read_aligned_six_hour_split_bytes("datasets/output-44_3D_54_BE_12_3C-aligned-and-21600-split-NO-UPDATE.csv", "Echo Dot 5th Gen (No Update)", 6)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/output-60_74_F4_1B_24_16--aligned-and-21600-split.csv", "Govee", 6)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/output-60_74_F4_1B_24_16-aligned-and-21600-split-NO-UPDATE.csv", "Govee (No Update)", 6)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/output-64_B7_08_A9_2B_20--aligned-and-21600-split.csv", "Amazon Light", 6)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/output-90_31_4B_71_8E_B6--aligned-and-21600-split.csv", "Netvue", 6)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/output-90_31_4B_71_B2_7B--aligned-and-21600-split.csv", "Litokam", 6)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/output-AC_84_C6_20_FE_4B--aligned-and-21600-split.csv", "TP-Link HS110 (US)", 6)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/output-EC_B5_FA_99_AC_15--aligned-and-21600-split.csv", "Philips Hue Bridge (US)", 6)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/output-EC_B5_FA_80_80_F4--21600-split.csv", "Philips Hue Bridge (EU)", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/output-1C_3B_F3_8D_29_4A--21600-split.csv", "TP-Link HS110 (EU)", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/output-FC_49_2D_34_98_28--21600-split.csv", "Echo Dot 3th Gen", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/output-20_DF_B9_3B_00_90--21600-split.csv", "Google Nest Mini", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/output-64_16_66_BE_44_9C--21600-split.csv", "Google Nest Learning Thermostat", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/output-A4_77_33_DF_C2_4D--21600-split.csv", "Google Home Assistant Speaker", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/output-40_A2_DB_2C_8A_68--21600-split.csv", "Amazon Echo Show 5th Gen", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/output-64_16_66_4A_65_71--21600-split.csv", "Google Nest Camera 1st Gen", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/output-50_C7_BF_5E_A8_48--21600-split.csv", "TP-Link Smart Bulb", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/output-F4_CF_A2_0C_41_F6--21600-split.csv", "Maxcio Smart Strip", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/output-64_FF_0A_88_AF_4A--21600-split.csv", "Sony KD-43XH8096", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/output-B0_C5_54_4A_30_B0--21600-split.csv", "D-Link DCS-8300LH-30B0", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/output-60_4B_AA_01_46_62--21600-split.csv", "Magic Leap 1", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/output-A0_85_FC_2F_7D_A0--21600-split.csv", "HoloLens 2", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/output-2C_26_17_56_C7_22--21600-split.csv", "Meta Quest 1", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/output-80_F3_EF_F7_F7_C1--21600-split.csv", "Meta Quest 2", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/output-C0_84_7D_2E_9C_86--21600-split.csv", "DreamGlass Air", 2)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

data <- read_aligned_six_hour_split_bytes("datasets/output-B0_4A_39_24_BB_A6--21600-split.csv", "RoboRock", 6)
dataframe_bytes[nrow(dataframe_bytes) + 1,] = data

write.xlsx(dataframe_bytes, file="output/test.xlsx", sheetName="Bytes", row.names=FALSE, append=TRUE)
