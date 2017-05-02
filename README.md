# WINLFFS
This repository is the Visual Studio solution to my student capstone project. 
It consists of all of the items used in creating my filesystem which is primarily aimed at the transfer of 
large files, greater than 4GB, as some current filesystems are unable to do so. Additionally, the ones that are
are not usually open source, making any modifications difficult if not impossible. For a better explaination, please go
to the [primary repository](https://github.com/bholmes94/didactic-spoon "primary repository"). Any general updates and
explainations are more likely to be found there. More specific information will be found or repeated here.

# Installation
To install, you can take the included winlffs.c file and open it within Visual Studio, which is the IDE that I used during development. You will also have to have the latest Dokan library installed and linked correctly in order to run it. I will be publishing a more detailed guide how to do this in the future. 

# Notes
There are a few things worth noting. There have been some errors coming up occasionally when the LFFSFindFiles callback is used. Usually this appears when the program is freeing up the unused data structure used to input an individuals file data. This is something that is still being investigated. Another item worth noting is that the buffer size used to move files around the system is VERY small at the moment. So it is worth wiping the drives directory if you want to remove something. There is a format utility I will upload which I have been using. It's basic and will clear the directory.
