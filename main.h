#pragma once
#include <QCoreApplication>
#include <cstdlib>
#include <stdint.h>
#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <thread>

#include "structs.h"
#include "getinfo.h"
#include "utils.h"

using namespace std;






