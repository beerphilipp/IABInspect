# IABInspect

## Abstract

In-app browsers (IABs) are heavily used components in mobile applications that allow app developers to display web content in native applications. Apart from simply rendering web content, such components provide the application with capabilities like the injection of JavaScript code and access to the website’s cookies. While these features are useful for developers, they also allow potentially unwanted applications (PUAs) to perform malicious activities on benign websites, such as session hijacking using JavaScript injection. This thesis presents a novel approach to analyzing app-to-web interactions in Android WebView, the main built-in IAB component in Android. We use a combination of static and dynamic analysis techniques to first build a blueprint of an application and then dynamically drive the execution of the application to calls where IABs are launched. Our controlled environment allows us to record the interactions between the app and the web content, effectively minimizing false positives. We implement our approach as a prototype called IABInspect and apply it to 1,000 popular Android applications. In total, we are able to dynamically trigger 508 IAB launch calls in 196 applications and find an injection of JavaScript code in 50 applications. Our results show that the use of WebViews is ubiquitous in Android applications and that the injection of JavaScript code is a common practice, underscoring the need for further research in this area.

## Folder Structure

- `00_preprocessing` contains code for the preprocessing step
- `01_static_analysis` contains code for the static analysis step
- `02_dynamic_execution` contains code for the dynamic execution step
