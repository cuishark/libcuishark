
#include <stdio.h>
#include <cuishark.h>
#include <gtest/gtest.h>
#include <thread>

void read_pcapfile(const char* filename)
{
  const char* argv[] = {"dummy", "-r", filename};
  cuishark_init(sizeof(argv)/sizeof(char*), (char**)argv);
  cuishark_capture();
}

TEST(Test1, packet_capture_count)
{
  read_pcapfile("in1.pcap");
  ASSERT_EQ(cuishark_num_displayed_packets(), 395);
  ASSERT_EQ(cuishark_num_captured_packets(), 395);
  cuishark_fini();

  // read_pcapfile("in2.pcap");
  // ASSERT_EQ(cuishark_num_displayed_packets(), 395);
  // ASSERT_EQ(cuishark_num_captured_packets(), 395);
  // cuishark_fini();
}

