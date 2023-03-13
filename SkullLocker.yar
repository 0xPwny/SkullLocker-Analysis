rule SkullLocker_Ransomware {
   meta:
      description = "SkullLocker Ransomware Rule"
      author = "The Hacker News B'Darija"
      date = "2023-03-11"
   strings:
      $s1 = "runas" fullword wide
      $s2 = "okok.exe" fullword wide
      $s3 = "skull.exe" fullword wide
      $s4 = "appMutexRun2" fullword ascii
      $s5 = "appMutexRun" fullword ascii
      $s6 = "appMutex2" fullword ascii
      $s7 = "appMutexStartup2" fullword ascii
      $s8 = "appMutexStartup" fullword ascii
      $s9 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s10 = "appMutex" fullword ascii
      $s11 = "runCommand" fullword ascii
      $s12 = "appMutexRegex" fullword ascii
      $s13 = "read_it.txt" fullword wide
      $s14 = "AlreadyRunning" fullword ascii
      $s15 = "<EncryptedKey>" fullword wide
      $s16 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii
      $s17 = "sleepOutOfTempFolder" fullword ascii
      $s18 = "droppedMessageTextbox" fullword ascii
      $s19 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no" fullword wide
      $s20 = "<RSAParameters xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" fullword wide
   condition:
      uint16(0) == 0x5A4D and                              
      filesize < 600KB and                                 
      8 of ($s*)                                         
}
