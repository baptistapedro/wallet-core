#include "TrustWalletCore/TWCoinType.h"
#include "TrustWalletCore/TWAnySigner.h"
#include "TrustWalletCore/TWCoinTypeConfiguration.h"
#include "TrustWalletCore/TWHDWallet.h"
#include "TrustWalletCore/TWPrivateKey.h"
#include "TrustWalletCore/TWString.h"

#include <iostream>
#include <string>

using namespace std;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
{
	std::string buf(reinterpret_cast<const char*>(data), size);
	buf.push_back('\0');
	try {
		TWHDWallet* walletImp = nullptr;
		auto secretMnemonic = TWStringCreateWithUTF8Bytes(buf.c_str());
        	walletImp = TWHDWalletCreateWithMnemonic(secretMnemonic, TWStringCreateWithUTF8Bytes(""));
        	TWStringDelete(secretMnemonic);
        	cout << "done." << endl;
        	cout << "Secret mnemonic for imported wallet: '";
        	cout << TWStringUTF8Bytes(TWHDWalletMnemonic(walletImp)) << "'." << endl;
        	cout << endl;
	} catch {
		return 1;
	}
	return 0;
}
