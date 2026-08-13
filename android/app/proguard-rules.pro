# JSch selects crypto implementations with Class.forName. Keep the complete
# implementation package so R8 does not remove classes such as jce.Random.
-keep class com.jcraft.jsch.** { *; }
-dontwarn com.jcraft.jsch.**

# BouncyCastle is looked up as a java.security.Provider via reflection/SPI;
# keep it intact so JSch can find the algorithms it registers.
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**
