#include <Windows.h>
#include <list>
#include <memory>
#include "sampler.h"
#ifdef _DEBUG
#include <iostream>

using namespace std;
#endif

cDataSampler::cDataSampler(uint32_t nSamples)
{
	this->nSamplers = nSamples;
	samples = std::unique_ptr<sDataSample>(new sDataSample[nSamplers]);
	ZeroMemory(samples.get(), nSamplers * sizeof(sDataSample));
	this->nSamplesTaken = NULL;
}

void cDataSampler::write_sample(const sDataSample & sample)
{
#ifdef _DEBUG
	//cout << "writing data sample(" << sample.transferred << ", " << sample.time << ")" << endl;
	//cout << "index=" << index << endl;
#endif
	auto cindex = ++index;
	if (cindex == nSamplers)
		cindex = index = 0;
	auto pSample = &samples.get()[cindex];
	while (InterlockedCompareExchange(&pSample->spinLock, 1, 0) != 0)
		Sleep(1);
	InterlockedIncrement(&nSamplesTaken);
	InterlockedExchange(&pSample->time, sample.time);
	InterlockedExchange(&pSample->transferred, sample.transferred);
	InterlockedExchange(&pSample->spinLock, 0);
}

ULONGLONG cDataSampler::speed_bps() const
{ 
	auto taken = nSamplesTaken;
	auto cnt = taken < nSamplers ? taken : nSamplers;
	if (cnt == NULL)
		return NULL;
	ULONGLONG ullBytesTransferred = NULL, ullTimeConsumed = NULL;
	for (size_t i = 0; i < cnt; i++) {
		auto pSample = &samples.get()[i];
		while (InterlockedCompareExchange(&pSample->spinLock, 1, 0) != 0)
			Sleep(1);
		ullBytesTransferred += pSample->transferred;
		ullTimeConsumed += pSample->time;
		InterlockedExchange(&pSample->spinLock, 0);
	}
	//get average
	ullBytesTransferred /= cnt;
	ullTimeConsumed /= cnt;
	if (ullTimeConsumed == NULL)
		ullTimeConsumed = 1;

	return static_cast<ULONGLONG>( (ullBytesTransferred / static_cast<double>(ullTimeConsumed)) * 1000.0); //formula: (B / T) * S, where B = bytes transferred, T = time consumed(in ms), S = 1 second in milliseconds.
}

cBandwidthThrottler::cBandwidthThrottler(uint32_t sample_rate, uint32_t nSamples):cDataSampler(nSamples)
{
	this->ullSpeedLimit = NULL;
	this->sample_rate = sample_rate;
	ZeroMemory(&tmp, sizeof(tmp));
}

void cBandwidthThrottler::write_sample(ULONGLONG bytes_transferred)
{
	tmp.transferred += bytes_transferred;
	if (sw.elapsed() >= sample_rate) {
		tmp.time = sw.elapsed();
#ifdef _DEBUG
		//cout << "writing sample: " << tmp.time << ", " << tmp.transferred << endl;
#endif
		cDataSampler::write_sample(tmp);
		ZeroMemory(&tmp, sizeof(tmp));
		sw.reset();
	}
}

void cBandwidthThrottler::enforce()
{ //enforces the speed limit(warning: will block)
	write_sample(NULL);
	ULONGLONG ullLimit = ullSpeedLimit;
	if (ullLimit == NULL)
		return;
	//http://stackoverflow.com/a/1067956
	auto speed = current_transfer_rate();
	if (speed > ullLimit) {
		ULONGLONG ullTransmitDelta = speed - ullLimit;
		DWORD dwWaitTime = static_cast<DWORD>(ullTransmitDelta * double(1000.0f/*1 second*/ / ullLimit));
		if (dwWaitTime > 1000)
			dwWaitTime = 1000;
		Sleep(dwWaitTime);
	}
}

DWORD cBandwidthThrottler::enforce_virtual()
{ //enforces the speed limit, without sleeping(for async socket).
	write_sample(NULL);
	ULONGLONG ullLimit = ullSpeedLimit;
	if (ullLimit == NULL)
		return NULL;
	//http://stackoverflow.com/a/1067956
	auto speed = current_transfer_rate();
	if (speed > ullLimit) {
		ULONGLONG ullTransmitDelta = speed - ullLimit;
		DWORD dwWaitTime = static_cast<DWORD>(ullTransmitDelta * (1000.0f/*1 second*/ / static_cast<float>(ullLimit)));
		//if (dwWaitTime > 1000)
		//dwWaitTime = 1000;
		if (dwWaitTime > 1000)
			dwWaitTime = 1000;
		return dwWaitTime;
	}
	else
		return NULL;
}

ULONGLONG cBandwidthThrottler::get_max_allowed_transfer()
{ //enforces the speed limit, without sleeping(for async socket).
	//write_sample(NULL);
	ULONGLONG ullLimit = ullSpeedLimit;
	if (ullLimit == NULL)
		return 0xFFFFFFFFFFFFFFFF;
	//http://stackoverflow.com/a/1067956
	auto bytes_currently_transferred = tmp.transferred;
	if (bytes_currently_transferred >= ullLimit)
		return NULL;
	return ullLimit - bytes_currently_transferred;
}