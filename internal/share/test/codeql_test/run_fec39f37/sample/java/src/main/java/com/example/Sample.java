package com.example;

public class Sample {
  public static void main(String[] args) {
    try {
      Runtime.getRuntime().exec("ls");
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
