#pragma once
#include "stopwatch.hpp"

struct sDataSample {
	uint64_t time, transferred;
	ULONG spinLock;
};

class cDataSampler {
public:
	cDataSampler(uint32_t nSamples);
private:
	int index = -1;
	uint32_t nSamplers;
	std::unique_ptr<sDataSample> samples;
protected:
	size_t nSamplesTaken;
	void write_sample(const sDataSample& sample);

	ULONGLONG speed_bps() const;//speed in BPS(bytes per second)
};

//uint64_t sample_rate, 

class cBandwidthThrottler:public cDataSampler {
public:
	cBandwidthThrottler(uint32_t sample_rate = 1000, uint32_t nSamples = 30);
	void write_sample(ULONGLONG bytes_transferred);
	void throttle(ULONGLONG ullBytesPerSecond)//renamed from set_transfer_rate_limit_bps
	{
		//set ullBytesPerSecond to NULL if you wish to disable the global Bandwidth meter.
		InterlockedExchange(&this->ullSpeedLimit, ullBytesPerSecond);
	};
	void set_sample_rate(uint32_t nSampleRate)//renamed from set_transfer_rate_limit_bps
	{
		//set ullBytesPerSecond to NULL if you wish to disable the global Bandwidth meter.
		InterlockedExchange(&this->sample_rate, nSampleRate);
	};

	ULONGLONG current_transfer_rate() { return cDataSampler::speed_bps(); };
	
	ULONGLONG max_transfer_rate() const { return ullSpeedLimit; };
	bool enabled() const { return ullSpeedLimit != NULL; };

	void enforce();
	DWORD enforce_virtual();
	ULONGLONG get_max_allowed_transfer(); //byte allowance for the current second
private:
	StopWatch sw;
	ULONGLONG ullSpeedLimit; //speed limit in BPS
	uint32_t sample_rate;
	sDataSample tmp;
};
