#pragma once
#include "pch.h"

struct Ip final
{
	static const int SIZE = 4;

	// constructor
	Ip() {}
	Ip(const uint32_t r) : ip_(r) {}
	Ip(const std::string r);

	// casting operator
	operator uint32_t() const { return ip_; } // default
	explicit operator std::string() const;

	// comparison operator
	bool operator==(const Ip &r) const { return ip_ == r.ip_; }

	bool isLocalHost() const
	{ // 127.*.*.*
		uint8_t prefix = (ip_ & 0xFF000000) >> 24;
		return prefix == 0x7F;
	}

	bool isBroadcast() const
	{ // 255.255.255.255
		return ip_ == 0xFFFFFFFF;
	}

	bool isMulticast() const
	{ // 224.0.0.0 ~ 239.255.255.255
		uint8_t prefix = (ip_ & 0xFF000000) >> 24;
		return prefix >= 0xE0 && prefix < 0xF0;
	}

	static Ip getMyIp(const char *interface)
	{
		struct ifaddrs *ifaddr, *ifa;
		int family, s;
		char host[NI_MAXHOST];

		if (getifaddrs(&ifaddr) == -1)
		{
			perror("getifaddrs");
			exit(EXIT_FAILURE);
		}

		for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
		{
			if (ifa->ifa_addr == NULL)
				continue;

			s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

			if ((strcmp(ifa->ifa_name, interface) == 0) && (ifa->ifa_addr->sa_family == AF_INET))
			{
				if (s != 0)
				{
					printf("getnameinfo() failed: %s\n", gai_strerror(s));
					exit(EXIT_FAILURE);
				}
				return Ip(host);
			}
		}

		freeifaddrs(ifaddr);
		exit(EXIT_SUCCESS);

		return Ip("0.0.0.0");
	}
	// operator가 없는 이유는 ip 자체가 비교가 가능한 자료형으로 구성되어 있기 때문.
protected:
	uint32_t ip_;
};
