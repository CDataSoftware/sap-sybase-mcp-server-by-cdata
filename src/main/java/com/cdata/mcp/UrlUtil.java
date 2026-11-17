package com.cdata.mcp;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class UrlUtil {
  public static String encode(String part) {
    return URLEncoder.encode(part, StandardCharsets.UTF_8);
  }
  public static String decode(String part) {
    return URLDecoder.decode(part, StandardCharsets.UTF_8);
  }
}
