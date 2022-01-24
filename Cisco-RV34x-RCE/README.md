## cisco-RV34x-RCE
The bug was found several mounths ago and it was reported by others.   
The cve-id should be CVE-2020-3451 or ....   

## Detail
The bug exists in upload cgi.   
```
  ......
  jsonutil_get_string(dword_22F84, &v24, "\"file.path\"", -1);
  jsonutil_get_string(dword_22F84, &haystack, "\"filename\"", -1);
  jsonutil_get_string(dword_22F84, &v25, "\"pathparam\"", -1);
  jsonutil_get_string(dword_22F84, &v26, "\"fileparam\"", -1);
  jsonutil_get_string(dword_22F84, &v27, "\"destination\"", -1);
  jsonutil_get_string(dword_22F84, &v28, "\"option\"", -1);
  jsonutil_get_string(dword_22F84, &v29, "\"cert_name\"", -1);
  jsonutil_get_string(dword_22F84, &v30, "\"cert_type\"", -1);
  jsonutil_get_string(dword_22F84, &v31, "\"password\"", -1);
  if ( v3 )
  {
    StrBufSetStr(v33, v3);
    v3 = 0;
    v10 = (char *)StrBufToStr(v33);
    for ( i = strtok_r(v10, ";", &save_ptr); i; i = strtok_r(0, ";", &save_ptr) )
    {
      v12 = strstr(i, "sessionid=");
      if ( v12 )
        v3 = v12 + 10;
    }
  }
  if ( !v24 )
  {
    puts("Content-type: text/html\n");
    printf("Error Input");
    goto LABEL_24;
  }
  StrBufSetStr(v34, v26);
  v13 = haystack;
  if ( haystack )
  {
    if ( strstr(haystack, ".xml") )
    {
      v14 = "Configuration";
    }
    else
    {
      if ( !strstr(v13, ".img") )
      {
LABEL_18:
        StrBufSetStr(v34, v13);
        goto LABEL_19;
      }
      v14 = "Firmware";
    }
    v25 = v14;
    goto LABEL_18;
  }
LABEL_19:
  v15 = v25;
  v16 = v24;
  v17 = StrBufToStr(v34);
  sub_11500(pathparam, file.path, filename);
  ......
```
Step into sub_11500:   
```
 ...
  sprintf(&s, "%s/%s", v7, v4);
  sprintf((char *)&v11, "mv -f %s %s", file.path, &s);
  debug("cmd=%s", &v11);
  result = v11;
  if ( v11 )
  {
    v10 = system((const char *)&v11);
    if ( v10 < 0 )
      error((int)"upload.cgi: %s(%d) Upload failed!", (int)"prepare_file", (const char *)0xAA);
    result = v10;
  }
  return result;
}
...
```
It's easy to inject a system command.    

It doesn't requrie authentication and you can get a shell with www-data privilege.
