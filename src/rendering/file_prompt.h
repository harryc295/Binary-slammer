/*
* Credit: https://learn.microsoft.com/en-us/windows/win32/learnwin32/example--the-open-dialog-box
*/

#ifndef FILE_PROMPT_H
#define FILE_PROMPT_H

#include <string>

#ifdef _WIN32

#define NOMINMAX
#include <windows.h>
#include <shobjidl.h> 

std::string GetFileDialog()
{
  HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED |
    COINIT_DISABLE_OLE1DDE);
  if (SUCCEEDED(hr))
  {
    std::string result;
    IFileOpenDialog* pFileOpen;

    hr = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_ALL,
      IID_IFileOpenDialog, reinterpret_cast<void**>(&pFileOpen));

    if (SUCCEEDED(hr))
    {
      hr = pFileOpen->Show(NULL);

      if (SUCCEEDED(hr))
      {
        IShellItem* pItem;
        hr = pFileOpen->GetResult(&pItem);
        if (SUCCEEDED(hr))
        {
          PWSTR pszFilePath;
          hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);

          if (SUCCEEDED(hr))
          {
            int strLength = WideCharToMultiByte(CP_UTF8, 0, pszFilePath, -1,
                nullptr, 0, nullptr, nullptr);

            result.resize(strLength);
            WideCharToMultiByte(CP_UTF8, 0, pszFilePath, -1, &result[0],
              strLength, nullptr, nullptr);

            CoTaskMemFree(pszFilePath);
          }
          pItem->Release();
        }
      }
      pFileOpen->Release();
    }
    CoUninitialize();
    return result;
  }
  return "";
}

#else

#include <cstdio>

std::string GetFileDialog()
{
  const char *cmds[] = {
    "zenity --file-selection --title='Open Binary' 2>/dev/null",
    "kdialog --getopenfilename . '*' 2>/dev/null",
  };
  for (const char *cmd : cmds) {
    FILE *pipe = popen(cmd, "r");
    if (!pipe) continue;
    std::string result;
    char buf[512];
    while (fgets(buf, sizeof(buf), pipe))
      result += buf;
    pclose(pipe);
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
      result.pop_back();
    if (!result.empty()) return result;
  }
  return "";
}

#endif // !_WIN32
#endif // !FILE_PROMPT_H
