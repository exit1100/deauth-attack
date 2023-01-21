TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap \
    -lpthread

SOURCES += main.c \
    beacon.c \

HEADERS +=
