#
# Makefile for the Linux Tse
#

obj-$(CONFIG_T_SE) += tse.o

tse-y := dentry.o file.o inode.o main.o super.o mmap.o read_write.o \
	      crypto.o keystore.o kthread.o debug.o

tse-$(CONFIG_T_SE_MESSAGING) += messaging.o miscdev.o
