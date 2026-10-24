#include <iostream>
#include <string>
#include "nist_compliance.h"

using namespace std;
using namespace NIST80088;

int main()
{
    cout << "================================================================================\n";
    cout << "  BITREAPERS: GENERATING OFFICIAL NIST SP 800-88 REV. 1 COMPLIANCE REPORTS       \n";
    cout << "================================================================================\n\n";

    DeviceMetadata dummyDrive;
    dummyDrive.devicePath = "/dev/nvme0n1";
    dummyDrive.friendlyName = "Samsung SSD 980 PRO 1TB Enterprise NVMe SED";
    dummyDrive.model = "MZ-V8P1T0BW";
    dummyDrive.serialNumber = "S5GXNF0R419823K";
    dummyDrive.firmwareRevision = "5B2QGXA7";
    dummyDrive.busType = "NVMe (PCIe Gen 4.0 x4)";
    dummyDrive.mediaTypeStr = "Solid State Drive (NVMe SED / AES-XTS 256)";
    dummyDrive.totalSizeBytes = 1000204886016ULL;
    dummyDrive.sizeGB = 1000.20;
    dummyDrive.logicalSectorSize = 512;
    dummyDrive.physicalSectorSize = 4096;
    dummyDrive.totalLBAs = dummyDrive.totalSizeBytes / 512;
    dummyDrive.hpaDetected = false;
    dummyDrive.hpaRemediated = true;
    dummyDrive.dcoDetected = false;
    dummyDrive.dcoRemediated = true;
    dummyDrive.securityFrozen = false;
    dummyDrive.sedHardwareEncryption = true;
    dummyDrive.nvmeSanitizeSupported = true;
    dummyDrive.nvmeFormatSupported = true;
    dummyDrive.ataSecureEraseSupported = false;

    SanitizationJobConfig cfg;
    cfg.level = SanitizationLevel::PURGE;
    cfg.methodName = "NIST SP 800-88 Rev. 1 Purge (NVMe Sanitize Block Erase & Cryptographic Key Purge)";
    cfg.passes = 1;
    cfg.operatorName = "Shashwat Srivastava (Lead Forensic SecOps Engineer)";
    cfg.organization = "BitReapers Enterprise CyberSec Labs";
    cfg.simulationMode = true;

    string startTime = "2026-10-24T05:15:00Z";
    string endTime = "2026-10-24T05:17:42Z";
    double duration = 162.0;

    // Execute rigorous Section 4.7 verification sampling
    VerificationDetails verif = NISTEngine::verifySanitization(
        dummyDrive,
        SanitizationLevel::PURGE,
        "0x00 / Deallocated Deterministic Read Zero (DZAT)",
        5.0,
        true
    );

    CertificateOfSanitization dummyCert = NISTEngine::createCertificate(
        dummyDrive,
        cfg,
        verif,
        startTime,
        endTime,
        duration
    );

    string dummyJson = "nist_sanitization_certificate_dummy.json";
    string dummyTxt = "nist_sanitization_certificate_dummy.txt";
    string dummyMd = "nist_sanitization_certificate_dummy.md";

    NISTEngine::exportCertificateJSON(dummyCert, dummyJson);
    NISTEngine::exportCertificateText(dummyCert, dummyTxt);
    NISTEngine::exportCertificateMarkdown(dummyCert, dummyMd);

    cout << "[✓] Successfully generated:\n";
    cout << "    - JSON Certificate     : " << dummyJson << "\n";
    cout << "    - Text Certificate     : " << dummyTxt << "\n";
    cout << "    - Markdown Certificate : " << dummyMd << "\n\n";
    cout << "Certificate ID       : " << dummyCert.certificateId << "\n";
    cout << "NIST Level           : " << levelToString(dummyCert.sanitizationLevel) << "\n";
    cout << "Verification Status  : " << dummyCert.verification.overallStatus << "\n";
    cout << "SHA-256 Fingerprint  : " << dummyCert.certificateHash << "\n";
    cout << "Digital Signature    : " << dummyCert.digitalSignature << "\n";

    return 0;
}
