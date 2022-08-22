#pragma once
#include "pch.h"

// ----------------------------------------------------------------------------
// Mac
// ----------------------------------------------------------------------------
struct Mac final
{
	static constexpr int SIZE = 6;

	// constructor
	Mac() {}
	Mac(const Mac &r) { memcpy(this->mac_, r.mac_, SIZE); }
	// copy constructor
	// 왜 call by reference를 하냐: 안하면 또 복사가 되기 때문..(?)
	Mac(const uint8_t *r) { memcpy(this->mac_, r, SIZE); }
	Mac(const std::string &r);

	// assign operator
	Mac &operator=(const Mac &r)
	{
		memcpy(this->mac_, r.mac_, SIZE);
		return *this;
	}

	// casting operator
	explicit operator uint8_t *() const { return const_cast<uint8_t *>(mac_); }
	explicit operator std::string() const;

	// comparison operator
	bool operator==(const Mac &r) const { return memcmp(mac_, r.mac_, SIZE) == 0; }
	bool operator!=(const Mac &r) const { return memcmp(mac_, r.mac_, SIZE) != 0; }
	bool operator<(const Mac &r) const { return memcmp(mac_, r.mac_, SIZE) < 0; }
	bool operator>(const Mac &r) const { return memcmp(mac_, r.mac_, SIZE) > 0; }
	bool operator<=(const Mac &r) const { return memcmp(mac_, r.mac_, SIZE) <= 0; }
	bool operator>=(const Mac &r) const { return memcmp(mac_, r.mac_, SIZE) >= 0; }
	bool operator==(const uint8_t *r) const { return memcmp(mac_, r, SIZE) == 0; }

	void clear()
	{
		*this = nullMac();
	}

	bool isNull() const
	{
		return *this == nullMac();
	}

	bool isBroadcast() const
	{ // FF:FF:FF:FF:FF:FF
		return *this == broadcastMac();
	}

	bool isMulticast() const
	{ // 01:00:5E:0*
		return mac_[0] == 0x01 && mac_[1] == 0x00 && mac_[2] == 0x5E && (mac_[3] & 0x80) == 0x00;
	}

	static Mac getMyMac(const char *interface)
	{
		std::string mac_addr_path = "/sys/class/net/";
		mac_addr_path += interface;
		mac_addr_path += "/address";

		FILE *stream;
		char buffer[18];
		int num;

		if ((stream = fopen(mac_addr_path.c_str(), "r")) != NULL)
		{
			memset(buffer, 0, sizeof(buffer));
			num = fread(buffer, sizeof(char), 18, stream);
			if (num)
			{ /* fread success */
				fclose(stream);
			}
			else
			{						/* fread failed */
				if (ferror(stream)) /* possibility 1 */
					perror("Error reading myfile");
				else if (feof(stream)) /* possibility 2 */
					perror("EOF found");
			}
		}
		else
			perror("Error opening myfile");

		return Mac(buffer); // 문자열 말고 바이트로 입력 받을 것. 문자열은 오래걸림.
	}

	static Mac randomMac();
	static Mac &nullMac();
	static Mac &broadcastMac();

protected:
	uint8_t mac_[SIZE];
};

namespace std
{
	template <>
	struct hash<Mac>
	{
		size_t operator()(const Mac &r) const
		{
			return std::_Hash_impl::hash(&r, Mac::SIZE);
		}
	};
}
