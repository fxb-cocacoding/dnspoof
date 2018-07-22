################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../checksum.c \
../dns_spoofing.c \
../file_io.c \
../main.c \
../networking.c \
../printing.c 

OBJS += \
./checksum.o \
./dns_spoofing.o \
./file_io.o \
./main.o \
./networking.o \
./printing.o 

C_DEPS += \
./checksum.d \
./dns_spoofing.d \
./file_io.d \
./main.d \
./networking.d \
./printing.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


