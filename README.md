# BackDroid

**BackDroid: Targeted and Efficient Inter-procedural Analysis of Modern Android Apps**
* Paper link: https://daoyuan14.github.io/papers/DSN21_BackDroid.pdf

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
We are cleaning the code of BackDroid and making it easy-to-use and extensible. The current version was set mainly for Daoyuan's computer and used some hard-code.

Our ultimate goal is to **make BackDroid a full-stack Android static analysis tool**, which can run as **a standalone tool** and also be used as **a generic SDK** to support customization for different problems.
