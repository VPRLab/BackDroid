# BackDroid

**BackDroid: Targeted and Efficient Inter-procedural Analysis of Modern Android Apps**
* Paper link: https://daoyuan14.github.io/papers/DSN21_BackDroid.pdf
* An earlier version of BackDroid had been used in our [[NDSS'19](https://daoyuan14.github.io/papers/NDSS19_OpenPort.pdf)] paper: ```Understanding Open Ports in Android Applications: Discovery, Diagnosis, and Security Assessment```.

If you use BackDroid or its code, please cite our DSN'21 paper as follows:
```
@INPROCEEDINGS{BackDroid21,
  AUTHOR =       {Daoyuan Wu and Debin Gao and Robert H. Deng and Rocky K. C. Chang},
  TITLE =        {When Program Analysis Meets Bytecode Search: Targeted and Efficient Inter-procedural Analysis of Modern {Android} Apps in {BackDroid}},
  BOOKTITLE =    {Proc. IEEE/IFIP International Conference on Dependable Systems and Networks (DSN)},
  YEAR =         {2021},
}
```

BackDroid was initially developed in a private BitBucket repo, and we are now migrating it to GitHub.
We also include some binaries and scripts of Amandroid and FlowDroid for a quick comparison between them and BackDroid.

We are cleaning the code of BackDroid and making it easy-to-use and extensible.
The current version was mainly set for Daoyuan's computer and used some hard-code.

Our ultimate goal is to **make BackDroid a *practical* and *full-stack* Android static analysis tool**, which can run as **a standalone tool** and also be used as **a generic SDK** to support customization for different problems.


## Required Tool/SDK to compile/run BackDroid

1. I use Eclipse to compile BackDroid, OldFlowDroid, and TestFlowDroid.<br>
**TODO:** use Gradle to make environment-independent compilation.

2. Need these two tools to generate _dexdump.log and _dex2jar.jar from an APK:
```
dexdump = '/home/dao/software/android-sdk-linux_x86/build-tools/28.0.3/dexdump'
dex2jar="/home/dao/software/dex2jar/dex2jar-2.1/d2j-dex2jar.sh"
```

3. Android SDK used by BackDroid (already in the lib folder):
```
Scene.v().extendSootClassPath("../lib/android-support-v7-recyclerview.jar");
Scene.v().extendSootClassPath("../lib/android-support-v4.jar");
......
Scene.v().extendSootClassPath("../lib/android_v28.jar");
Scene.v().extendSootClassPath("../lib/android_v23.jar");
Scene.v().extendSootClassPath("../lib/android_v19.jar");
```

4. Android SDK used by FlowDroid:
```
public static String AndroSDK = "/home/dao/software/android-sdk-linux_x86/platforms";
```

5. I use Java 7 (Open JDK) to compile in Eclipse, but use Java 8 (Oracle) to run the code:
```
Scene.v().setSootClassPath("/usr/lib/jvm/java-8-oracle/jre/lib/rt.jar");
```
