#pragma once

#include <cstdint>
#include <cstring>
#include <string>

// ----------------------------------------------------------------------------
// Mac
// ----------------------------------------------------------------------------
struct Mac final
{
	static constexpr int SIZE = 6;

	// constructor
	Mac() {}
	Mac(const Mac &r) { memcpy(this->mac_, r.mac_, SIZE); }
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

	static Mac getMyMac(const char *addr_path)
	{
		FILE *stream;
		char buffer[18];
		int num;

		if ((stream = fopen(addr_path, "r")) != NULL)
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

		return Mac(buffer);
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
