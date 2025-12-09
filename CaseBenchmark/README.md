=== Semgrep Example Coverage Summary ===
[python]  Rules:  254  With example:  254  Coverage: 100.00%
[javascript]  Rules:  155  With example:  155  Coverage: 100.00%
[java]  Rules:  122  With example:  122  Coverage: 100.00%
[go]  Rules:   76  With example:   76  Coverage: 100.00%
[php]  Rules:   62  With example:   62  Coverage: 100.00%

=== Overall ===
Total Rules:  669  With example:  669  Coverage: 100.00%



=== CodeQL Example Coverage Summary ===
[java]  Rules:  122  With example:   91  Coverage: 74.59%
[python]  Rules:   50  With example:   23  Coverage: 46.00%
[go]  Rules:   36  With example:   32  Coverage: 88.89%
[javascript]  Rules:   99  With example:   78  Coverage: 78.79%
 === Overall ===
Total Rules:  307  With example:  224  Coverage: 72.96%

 ✅ 统计完成，结果写入 /home/cbb/SAST-Rule-Migrate/CaseBenchmark/CodeqlSample/codeql_example.json

直接扫描后缀名
 === CodeQL Example Coverage Summary ===
[java]  Rules:  122  With example:  115  Coverage: 94.26%
[python]  Rules:   50  With example:   48  Coverage: 96.00%
[go]  Rules:   36  With example:   36  Coverage: 100.00%
[javascript]  Rules:   99  With example:   92  Coverage: 92.93%

=== Overall ===
Total Rules:  307  With example:  291  Coverage: 94.79%

✅ 统计完成，结果写入 /home/cbb/SAST-Rule-Migrate/CaseBenchmark/CodeqlSample/codeql_scan.json

=== Uncovered Rules ===
[java] Uncovered Rules:
  - java/ql/src/Security/CWE/CWE-926/ContentProviderIncompletePermissions.ql
  - java/ql/src/Security/CWE/CWE-926/ImplicitlyExportedAndroidComponent.ql
  - java/ql/src/Security/CWE/CWE-732/ReadingFromWorldWritableFile.ql
  - java/ql/src/Security/CWE/CWE-200/SpringBootActuatorsConfig/SpringBootActuatorsConfig.ql
  - java/ql/src/Security/CWE/CWE-829/InsecureDependencyResolution.ql
  - java/ql/src/Security/CWE/CWE-1104/MavenPomDependsOnBintray.ql
  - java/ql/src/Security/CWE/CWE-524/SensitiveKeyboardCache.ql
[python] Uncovered Rules:
  - python/ql/src/Security/CWE-732/WeakFilePermissions.ql
  - python/ql/src/Security/CWE-326/WeakCryptoKey.ql
[javascript] Uncovered Rules:
  - javascript/ql/src/Security/CWE-326/InsufficientKeySize.ql
  - javascript/ql/src/Security/CWE-313/PasswordInConfigurationFile.ql
  - javascript/ql/src/Security/CWE-862/EmptyPasswordInConfigurationFile.ql
  - javascript/ql/src/Security/CWE-830/FunctionalityFromUntrustedSource.ql
  - javascript/ql/src/Security/CWE-830/FunctionalityFromUntrustedDomain.ql
  - javascript/ql/src/Security/CWE-300/InsecureDependencyResolution.ql
  - javascript/ql/src/Security/trest/test.ql