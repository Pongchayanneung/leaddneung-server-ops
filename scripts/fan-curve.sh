#!/bin/bash
# runs as root (invoked via sudo) — write directly to sysfs
H=/sys/class/hwmon/hwmon9
CPU_T=(50 55 60 65 70 75 80 85); CPU_P=(0 30 70 110 150 190 230 255)
GPU_T=(50 55 60 66 72 78 82 86); GPU_P=(0 25 60 120 175 220 245 255)
for i in $(seq 1 8); do
  echo ${CPU_T[$((i-1))]} > $H/pwm1_auto_point${i}_temp
  echo ${CPU_P[$((i-1))]} > $H/pwm1_auto_point${i}_pwm
  echo ${GPU_T[$((i-1))]} > $H/pwm2_auto_point${i}_temp
  echo ${GPU_P[$((i-1))]} > $H/pwm2_auto_point${i}_pwm
done
echo 1 > $H/pwm1_enable
echo 1 > $H/pwm2_enable
