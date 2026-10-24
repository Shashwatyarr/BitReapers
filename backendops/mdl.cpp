#include <iostream>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <array>
#include <fstream>
#include <sstream>
#include "nist_compliance.h"

using namespace std;
using namespace NIST80088;

string execCommand(const char *cmd)
{
    array<char, 128> buffer;
    string result;
#ifdef _WIN32
    unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd, "r"), _pclose);
    if (!pipe) throw runtime_error("_popen() failed!");
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
#else
    unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) throw runtime_error("popen() failed!");
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
#endif
    return result;
}

int main()
{
    try
    {
        cout << "=================================================================\n";
        cout << "  BITREAPERS - NIST SP 800-88 MEDIA DETECTION & AUDIT (LINUX)    \n";
        cout << "=================================================================\n\n";

        ofstream txtfile("storage_report.txt");
        ofstream jsonfile("storage_report.json");

        string devices = execCommand("lsblk -d -o NAME,TYPE,SIZE,MODEL,SERIAL,TRAN -J 2>/dev/null || echo '{\"blockdevices\":[]}'");
        string devicesText = execCommand("lsblk -d -o NAME,TYPE,SIZE,MODEL,SERIAL,TRAN 2>/dev/null || echo 'No devices detected'");

        txtfile << "=== Detected Storage Devices (lsblk output) ===\n";
        txtfile << "Generated at: " << getISO8601Timestamp() << "\n\n";
        txtfile << devicesText << "\n\n";

        string deviceList = execCommand("lsblk -nd -o NAME,TYPE 2>/dev/null | awk '$2==\"disk\" {print $1}'");
        txtfile << "=== Device Metadata (SMART Info & NIST 800-88 Security State) ===\n";
        
        istringstream iss(deviceList);
        string dev;
        vector<string> jsonDevices;

        while (iss >> dev)
        {
            txtfile << "---- /dev/" << dev << " ----\n";
            string info = execCommand(("sudo smartctl -i /dev/" + dev + " 2>/dev/null").c_str());
            txtfile << info << "\n";

            string secInfo = execCommand(("sudo hdparm -I /dev/" + dev + " 2>/dev/null | grep -A 8 'Security:'").c_str());
            if (!secInfo.empty()) {
                txtfile << "Security Frozen State:\n" << secInfo << "\n";
            }

            string jsoninfo = execCommand(("sudo smartctl -i -j /dev/" + dev + " 2>/dev/null").c_str());
            if (!jsoninfo.empty() && jsoninfo.front() == '{') {
                jsonDevices.push_back(jsoninfo);
            }
        }

        jsonfile << "{\n";
        jsonfile << "  \"timestamp\": \"" << getISO8601Timestamp() << "\",\n";
        jsonfile << "  \"compliance\": \"NIST SP 800-88 Rev. 1 Guidelines for Media Sanitization\",\n";
        jsonfile << "  \"lsblk_devices\": " << (devices.empty() ? "{}" : devices) << ",\n";
        jsonfile << "  \"smart_devices\": [\n";

        for (size_t i = 0; i < jsonDevices.size(); i++)
        {
            jsonfile << jsonDevices[i];
            if (i + 1 < jsonDevices.size())
                jsonfile << ",";
            jsonfile << "\n";
        }

        jsonfile << "  ]\n";
        jsonfile << "}\n";

        txtfile.close();
        jsonfile.close();

        cout << "Reports saved as storage_report.txt and storage_report.json\n";
    }
    catch (const exception &e)
    {
        cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
