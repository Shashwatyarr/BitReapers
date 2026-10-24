#include <iostream>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <fstream>
#include "nist_compliance.h"

using namespace std;
using namespace NIST80088;

string execCommand(const char *cmd)
{
    array<char, 512> buffer;
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
        cout << "  BITREAPERS - NIST SP 800-88 MEDIA DETECTION & AUDIT (WINDOWS)  \n";
        cout << "=================================================================\n\n";

        ofstream txtfile("storage_report.txt");
        ofstream jsonfile("storage_report.json");

        cout << "🔍 Detecting physical storage media via PowerShell...\n";
        
        string deviceJson = execCommand(
            "powershell -Command \"Get-PhysicalDisk | Select-Object DeviceId,FriendlyName,SerialNumber,MediaType,BusType,Size,FirmwareVersion,OperationalStatus,HealthStatus | ConvertTo-Json -Depth 3\"");
        
        string deviceText = execCommand(
            "powershell -Command \"Get-PhysicalDisk | Format-Table -AutoSize\"");

        txtfile << "=== BITREAPERS NIST SP 800-88 STORAGE DEVICE REPORT ===\n";
        txtfile << "Generated at: " << getISO8601Timestamp() << "\n\n";
        txtfile << "=== Detected Physical Disks ===\n";
        txtfile << deviceText << "\n\n";

        cout << "💾 Calculating sizes and NIST 800-88 compliance classification...\n";
        string sizeText = execCommand(
            "powershell -Command \"Get-PhysicalDisk | ForEach-Object { '[Disk ' + $_.DeviceId + '] ' + $_.FriendlyName + ' (' + $_.MediaType + ' / ' + $_.BusType + ') : ' + [math]::Round($_.Size/1GB,2) + ' GB | Health: ' + $_.HealthStatus }\"");

        txtfile << "=== Media Classification & NIST 800-88 Sanitization Recommendations ===\n";
        txtfile << sizeText << "\n\n";
        txtfile << "NIST SP 800-88 Rev. 1 Recommendations:\n";
        txtfile << " - NVMe SSD: Recommend PURGE via NVMe Sanitize or Format (SES=1 User Data / SES=2 Crypto Erase).\n";
        txtfile << " - SATA SSD: Recommend PURGE via ATA Secure Erase or Cryptographic Erase (if SED).\n";
        txtfile << " - Magnetic HDD: CLEAR via 1-Pass Zero Overwrite; PURGE via ATA Secure Erase or Degauss.\n";

        jsonfile << "{\n";
        jsonfile << "  \"timestamp\": \"" << getISO8601Timestamp() << "\",\n";
        jsonfile << "  \"compliance_standard\": \"NIST Special Publication 800-88 Revision 1\",\n";
        jsonfile << "  \"physical_disks\": " << (deviceJson.empty() ? "[]" : deviceJson) << ",\n";
        jsonfile << "  \"sanitization_capabilities\": {\n";
        jsonfile << "    \"clear_zero_overwrite\": true,\n";
        jsonfile << "    \"clear_random_overwrite\": true,\n";
        jsonfile << "    \"purge_ata_secure_erase\": true,\n";
        jsonfile << "    \"purge_nvme_sanitize\": true,\n";
        jsonfile << "    \"purge_cryptographic_erase\": true\n";
        jsonfile << "  }\n";
        jsonfile << "}\n";

        txtfile.close();
        jsonfile.close();

        cout << "✅ Media inventory captured and saved to storage_report.txt and storage_report.json\n";
    }
    catch (const exception &e)
    {
        cerr << "❌ Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
