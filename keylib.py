"""Utilities that reproduce the sa015bcr key-derivation pipeline."""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Dict, List, Mapping, MutableMapping, Sequence

PASSWORD_MAP: Dict[int, str] = {
    0x00: "01EgjpxczBk2pRSn6r/UfgIDriRFHxEtkT7dlcdQOpq2sA9QAAfP9QboFog6A=",
    0x01: "0117qfOWmaS+aLoZhpXHhTMFDyTkw81sTKBPWQ1yjCF8EA9QABrH544gNgWsk=",
    0x02: "01Qf3tZSjgbwVBQKHDLz9ULsn9nw750uoM0b9SMzV3LwAA9QACjCnULKmiTps=",
    0x03: "01E9oqp4yP5VihNGPcQetsG1NKEs9nv/iTskE8KbIY72MA9QADsFYwilY9l4w=",
    0x04: "01OPGDOr5wfow50t1CU7I3JicRmz2vvvaLEgT6Ebswc/sA9QAEo0HoWPLJ09M=",
    0x05: "01prOb95CCkDacmrShpq/VIckn+Q/Fwj0G6R9thQa9htUA9QAFMw33N2G8CU0=",
    0x06: "01qDmfPBEQuLaIVPR5ZfMa2rO95nrIxHxAPqvEQcgUhLQA9QAGcMUlBRPXGN8=",
    0x07: "01KYKG18R3D11hGjiwKyQDvYx5ficqkWEG6jK64tN66lQA9QAHKMlYGNIrD10=",
    0x08: "019v8cUcVxkxyKbRrGWtiAsT6pBvBLU8N2wU7cow6ArHQA9QAICShM+47PPPw=",
    0x09: "01QNMDCn/jgSWzItILtWJfcvtUTJwQfF2wkb7017CdG9wA9QAJD1I90eUmcCk=",
    0x0A: "01iJiF+TSGW7dW6xvhFLuZS6B2YXFrMD/t5MjJJawuuRMA9QAKacYEn6g4J+Y=",
    0x0B: "01UMceMrYqtcbENupWRz7yznnS+Xn2GzRyWq+R+Z6ahP0A9QAL+Qj5NVH94J0=",
    0x0C: "01kyA2o5LpL8YH5MBMFD3W9DsxXgicUs/8fo7m0ZIBwWYA9QAMBnOpJOM8uOw=",
    0x0D: "01kt3MgJFSQpTPAQip58UUTbHwdCSDhCDl1Rd8Pz0vDLMA9QANkDrA/CmpkMQ=",
    0x0E: "01mSli7y+6z4jvrVnK7HPT/wHATxQ1H/087iu/xmH5hRMA9QAOIk+fWrmFQmU=",
    0x0F: "01fWt+jeoquSXjUTVzv9x9+D1PmAeV0FIhp0IekJWDwp8A9QAPZ1p+aH47m2g=",
    0x10: "013moyXqATbwKjPVaOIeN/TluRC8LGAJbsnjjhfUuuGDcA9QAQTiRv5JYkVXo=",
    0x11: "01ySQtRhF7KwiA400ROVdFekFU21F5Y/CY28OBkJYEWiQA9QARMU4JgJIGE9w=",
    0x12: "01IcbBLx6RLaWPRfBWf+K1SwkNpPePfj1epEVMsADG+ggA9QASTFVrXjLQBng=",
    0x13: "01ACuiLUgDXMJrSog+z62id1VmIQ6dHc49sJRshHEansYA9QATntDga4Rxa9o=",
    0x14: "01JY84hJ+hKtkWYVqyHBw+xRTGV/IZs5uA1evVqDZCn6wA9QAU5Ny6MonhGcc=",
    0x15: "01rjH7NzXc5RbS53vUgvQN9+jckFgYNOZWTgfSvIKSkuwA9QAVdudKuQO8rHg=",
    0x16: "01/X/JdnSmV3IY9VPNdNSmhh3DkNbnOAbdu3DWIubH+d4A9QAWr9B2HXPioFk=",
    0x17: "013JHcHyfSM1dpF01X8giEKXIcoFQR9VbmeEb7/1jiFaYA9QAX7/gR11r9EpQ=",
    0x18: "017j1mipxYL+QvqrCgK++vFuGtEVOPY1GPtw8qiK+h3e8A9QAYQHgzPusFcEw=",
    0x19: "01SuwMBiAR/rZflwq3uPI4MMRfIXNCrk8r/Vci6PpsbKwA9QAZND3Ysupai7M=",
    0x1A: "01Ot3Mo4/WJmi6adiIXg5GyjZrzCu4A4j3i/IHl9rZuFEA9QAacuR7oa9Epnk=",
    0x1B: "01scyH+ngv2woaekNKjgxCV09vccisi+jSa/Jppuz54mQA9QAbt/r0WxkjG3Q=",
    0x1C: "01EC6E3v8dP0oKiL4CA8VE0sty6ZKc2jIw+hARTuQO24cA9QAcyymPYwM/eMw=",
    0x1D: "01N7nOPGHf7rOnYyqVVO0K/BUkd4UAWjhPqoSBMuWIoaIA9QAd24eZ7uU0ip0=",
    0x1E: "01ttZKBsMNKn4f3k/wAgAYVEjZFR/FB6Tk8qREu0F7/Z4A9QAe99wnSf6u6iY=",
    0x1F: "01Of6rerqNDxDGguHJreFve/Zm+5AqAo1znprBwBfLO34A9QAfR4gKGAHkKsM=",
    0x20: "01PaFtFBg4wgFmeL9OLrCmyIae0005xF/DyxR9rwfYts0A9QAgJpja4PiF7ps=",
    0x21: "01qNI57WWL3nbJId1G26pImcf/mcPgbBDqJga5A/gYdHgA9QAhWoy6dg+BJfQ=",
    0x22: "01DCrzYhbboVGpeEvALJ/9SaM+3kaVAbFQmRXqE+Kwg5QA9QAiUiwV6j9hKmU=",
    0x23: "01jlWnPKxj/k9Zpm7nUqCC2aFJEaH3zjiC2qcZiJwyIsQA9QAjob/j07DFV6E=",
    0x24: "01vJ9x3RUojn7WEp0YRcxR5YRGks/mE4wkxESXmR4xBvUA9QAkE5AQcBRppro=",
    0x25: "01LZ7UJ0GeKFcsWLaNJ9LSYyAhFxU+gigPEn9XVbagg9cA9QAlA1ONWgO+c8U=",
    0x26: "01dNbFPI5oBCUkpMCsQnLSZzKrM1H96xiUFBgDjHQxItUA9QAmdy0CKDkIEfQ=",
    0x27: "01XRo3XLLiF67ghT6iI64fvqPpUTk2n+RzoJZTivW3h9AA9QAn778LLcThkGU=",
    0x28: "01X87tXIT6hLvIUUnQuiOv7Za/a0sB9RjOI91J2IcQYeAA9QAo9IP34SpBGjA=",
    0x29: "01JP1whfM4S39KDVm/gVYMkIFkKPRZ0ULEhkV7LIw/TVUA9QApikKF/1FvPuQ=",
    0x2A: "01joamnu17tv3VBvTeWzJzzdzArVA5gmcR65ub3TOAR9wA9QAqJ3l2ioc4BW4=",
    0x2B: "01uH6Nc9wxAS8OPlAdpKgRHcikd1KlKMYg6t1AwyIgHCgA9QArQ6ePG2dr7yU=",
    0x2C: "01BWj7PSCVuJntPzSrdI8r7b7a2+gNvH6w51UGR/cpXEAA9QAsj5LJEIf1bSE=",
    0x2D: "01ZFH1fw0jHvHLJbiaQ38t8HAiGo9LNCDxyQgHQxIrr3UA9QAtmUnvvvP9B+Q=",
    0x2E: "01mmxF6BoUeo1UUh/c2UolFcMKWOhyhBC1TuGnSYZWVSQA9QAurXrnNjNZwnQ=",
    0x2F: "01W4FzhLUL9wqImi0025OzMzmKrZJg30bV2eSbJk3e1RcA9QAvyg04+OuUvaQ=",
    0x30: "01gemYz53qoHDPbQYqZbYFx46m91zeXNzFMr1gn4fTpXMA9QAw6mglW406XbY=",
    0x31: "010CrGdMA5uIDYXvcFh7Y/8ogCdkhxIrTeiGnBAv6PRmwA9QAxEG7h69ZK1Bk=",
    0x32: "01vjHv/Y2ojwR7ZYBTZyMonfgi7DBb2OtbXuPbRFm4UGIA9QAyLzBDKxTt4po=",
    0x33: "01cAqBvmTVdkJit9y6CVdP4VWxQ4ycD/CW7q6dIltZ/qAA9QAzHQZWY0PnG5A=",
    0x34: "01qQGdoDxLwI8EusXrOOdm9BrNKgIvhHdaHG1gN85tgVYA9QA0lun7ALvDurU=",
    0x35: "01ve200zlvSJ2wv5WEhXlqAgtHDVjYDaWepHLmyuBGUK8A9QA1XqhJiQyYurQ=",
    0x36: "01PrIImoc9I8LR2KMWN/rbWu2tZq5rQiB2OQU3hZziKwkA9QA2puW6c/M4MCQ=",
    0x37: "01ioZ1mqryEXr9YGQuxku+p8jT/+YomXXC7BC6rmJE4vQA9QA3xceIvel9T64=",
    0x38: "01XzgqDd/KFYJ+dE52WTv5F71YtawWa5EO9HNQtYJLDvkA9QA4Wnc1e7c+HpM=",
    0x39: "01es3ZegqxoU+adkZH+XJDb4B3GyR+tWg2SuRyNf5oQFkA9QA5bYj/MCg3E/A=",
    0x3A: "010D2FO5FIeElRt4fi27P7sW+utpG3v32awdirhlNEu6EA9QA6IDFotEVBUME=",
    0x3B: "01kl25BDTTPrP4WLY5RKGskcWBxE5tv6pX9TuaC2ykwesA9QA7qaLOLgrb8oA=",
    0x3C: "01SvN0LxbPo9hHn05TJwK+znxWI+Vav5MPOLMpSK4mQWEA9QA8UymqObSvUMQ=",
    0x3D: "01qHdMY9bAKl99Q5MHTwML8kKKGRXSONSA7FthJ1tY5qoA9QA9QE6tHYhSE+s=",
    0x3E: "01GrFzSAf5Xm4HXLxaiheJbWzR0zu3C07FqPGNWAGI6t0A9QA+QPx458xUphY=",
    0x3F: "01VE8RHtZXUg5lqqe5K5qTznezIStuUSN6v1gKLp3NwdYA9QA/ZdRebAxMuCY=",
    0x40: "01KVci+9cRyd+acCN3IZXXViP+C5lFjSwlUzdBNjgb3xcA9QBABv7puNYtodM=",
    0x41: "01JGvEGYZpzfX3JvP6O/Iby8XFHEXO9xPG3KMwFlZmUqkA9QBBCz42u+uMymA=",
    0x42: "01BIVUkUjQTNmZKefxkEwVhAE3QJmB+2iOK8f3vDwlUMMA9QBCH6kCK+qfxd4=",
    0x43: "01z7UJAuMVWZ+BZj+t9bgvXx7w4QzgzqJddoD9kiNkTaYA9QBDdcsbk9mJlhI=",
    0x44: "01wX/M+8OSmMddgdf/RP/915L4+hkddWQgyftyxVSUMjkA9QBEoiYel4NxfWQ=",
    0x45: "01ZDQ8a/4/tsA1B+Lpfk2RYhNPwO6uxeT57EjdPTeyexMA9QBFuHtz5G/LEGo=",
    0x46: "0121ywdh7p0YK6MS+O9Vg8iaFMAdm6faGBe/oPIeJ6s24A9QBGCq7l1dfR8eU=",
    0x47: "01pyGjCwZdEc7KXmZXABawQTAN1qyPtW25zV8QHjLoXIMA9QBHYdF9TQJZ0zU=",
    0x48: "01vqoVRwRXMN+j3qPQU4Enfg1lbBB81zZEH0mrr8kPMR4A9QBITWUzXH5ASok=",
    0x49: "01iElbTKH/fTSqfg7XkUe0OI323dEaQ5lgDvwX5vXpexIA9QBJo/7Ta5M+EoM=",
    0x4A: "01OSYuyfXqL1VH+tSid74ygjvUen6cBqWmYXPmsgqLcUIA9QBK/42PlTHvQdU=",
    0x4B: "01fIYk5Er5cxIQH2NFDMx+WIWhsp1nKYOtccC+hPZF2UYA9QBLPSAaanbuLCI=",
    0x4C: "011hUcvLdOKLh/18xTobX/izWo0FmrBpcRyQdhZltbrSgA9QBMKd/5SGi45lM=",
    0x4D: "0184DBLyV08bk/jHN6sPCuAcCJh/Vm94YoYykYlCVetM8A9QBNg+SezK03fOQ=",
    0x4E: "01yuxrZYDNQGYewJ1HFZTLg6xj+KdGcNQ+HuWhpzPxm7EA9QBOt/WQcZ+ANHk=",
    0x4F: "01yuesDD9Y9frtuvmraPC3RSmSOzWiPKbJXyLXaEpAkLcA9QBPrCb4jC05KAo=",
    0x50: "01VJSfB7SbJVqUFBPSYuETHjCXiLFUau1mtUOrDTl5s/sA9QBQS40Lk4QfTtk=",
    0x51: "01zOwhn+ibvdc+OA9ftpIeM+SSAEL7a4fndW29SlgCrVoA9QBRF82euDDSHNE=",
    0x52: "01VxdwoUMrFgZ5JjVmVkexNEtN8iSN5Y2E4jFZUPXtbWAA9QBSB/Le2nxOd0c=",
    0x53: "01b5Mv19HMCx5nQ6M1RVt11IXiPH36f7+f4AXIM9uogpcA9QBTgxvxDckYCng=",
    0x54: "016bL6REfdmLmr5tojQEjKXZKR7eLNeoV2vdXBWUmh13cA9QBUUZdw/ytoL4Q=",
    0x55: "014qYwIvlbFdYpXrdYojAxop4CIlC9G9nuhRbfks9N/F0A9QBV1NzRJC5k4Lk=",
    0x56: "01QKHQO+mtClv/WGKOAoC/vLZVR1RFiduUlfs6dOSPXzcA9QBWyV/iReGhSP0=",
    0x57: "01DtRqK/98CkTMbc22cPcY/FhX61dVz7x4T49f8sd2oBQA9QBX2H2yX1EBjiQ=",
    0x58: "01g70NsnVWcn4QksSemSrNgvtzAP8wOV5Rx+zj7za/G9EA9QBYsMTnKVsCllA=",
    0x59: "01z6l1JM04AXEA1nwdhb+ErIV/wOm9HpJlDXETkgwdgPwA9QBZ/UWVnL5VoRk=",
    0x5A: "01k7VtuxhfcdpSO5EhtIwWLsTJuFMwPxR2ygR7KcH8TRIA9QBanhqgDcd5bns=",
    0x5B: "01YZHoz+bgUlpbGtYI3lqzkb2ct+fNyJSoEotr/MSjSywA9QBbTv/hN0CXFd8=",
    0x5C: "01tbFqqW77Y1YOAwQoqu9humgAFq2iN11g4F6IuouS1SEA9QBcmQ+XR1x/Wq0=",
    0x5D: "01K7KyedjtK1FUJGTCHtbNc7z19OB6SLsSHghnIZ9ljZsA9QBd6gGvDhmDLFk=",
    0x5E: "011Df9+pUyQYKwDM3WTZfyEFPDkQWMMuGPqn4PbGS5t4wA9QBeBEgUb2K3FQg=",
    0x5F: "01TWrQlCKdfJQybPGGoz3tpT8MFZ/LeHuij5EXF8kbZp0A9QBfaRCtjq0OxB8=",
    0x60: "01ANdOLAkpbZZtx7Nto7+KqMC8aZVAE50d19ag7yc7C1kA9QBgrW7LpBvK2Oc=",
    0x61: "015E+paPsIxmIdmmTBTSOBnWo9aY/emUucCYV/PKyjW/sA9QBhvcZ0NMLnEfw=",
    0x62: "01ObjJ39VOqLnSYKu8HbcrpgfXhYmdo7bXh4eI4+T1DFYA9QBiqTuaRV9nhck=",
    0x63: "01kbRBTRJ8D0BFxab6+lrzurKpqkctvir3ZCktRnxuy44A9QBjEhBRb+slbNA=",
    0x64: "01DfTiizrShgltjeVmKqZZMdnHj3pJOMS16tknEPy1n1UA9QBkGGpP/xTJKtY=",
    0x65: "01ZfKqtWzR8XTYB4FSa/vPMlJinPAappQg8MfIykdMUPMA9QBl9J2VuRM5g8E=",
    0x66: "01r2qg63EuUk1QxLWTgOdDFNv8JQoRMA1/kbU7R3b0ApwA9QBmu/ACR7khW/4=",
    0x67: "01skPXmFaoToRYv7I3BcxjdD4+pJhqenhBs4Vi+ssn52AA9QBntVTzkwIx+wc=",
    0x68: "0107qAr3iF27YSA60xiiMGN/55oeQfeeN4c5AsjGbhVCoA9QBoK903cZU41gE=",
    0x69: "01PPXyxK3bVxBrkWXwohfGw7up+Qgofr74nolAO+NxZ6IA9QBpZhshEs+GhZo=",
    0x6A: "01chwsDcqPPLKIGltS3FqG7D7JjwKHA+nkUSXObUL87B8A9QBqS3DrKdtfCjM=",
    0x6B: "01LCvbbI9iIU1yj7G9L9aN25gKZsJUrL93Aocv/w782SQA9QBr7RyE4mgSlaA=",
    0x6C: "01kiEDI80tGQY/svtJ3HHwTPV95UpH8piJduej7bzaJ/AA9QBsMDJENupylLU=",
    0x6D: "01PHgrYTFnjTDT1f6tiBfA5mLVDBxLMCpMNGt23tzXZw8A9QBtMlj9swYhAmI=",
    0x6E: "01X77yfF2lPxce6uAQXCXWvT+mjXCohqqqDp6VXJV+nBcA9QBuc0R9D4JUGG8=",
    0x6F: "014OeLd2WJ/oCDk+DS3wF6wS1unM1PJqgPr8/TEm1+qYQA9QBvcLGX6EPVGjw=",
    0x70: "01tT0WurB5VGLTCpBymxN08mrMa7NgbRcTAdo300OZ42EA9QBwibmcH6cD2F4=",
    0x71: "01PCKu7tgl37tG8YbfyNM4hC89owicvH9J99V8ls4QfCwA9QBxbdnvgqdjbG0=",
    0x72: "01dOYAmP8+wXPiL4tL8AjV+0sGJt06aZ4IIH4sa55YzIoA9QByqkW8mvMZu68=",
    0x73: "01tKqYeMjuH+Ypl/XgfTytMYW8ff5/XdqjbHo1A6pe4hEA9QBzUNkoyWoSXd8=",
    0x74: "01lnttrN8oej/CIfpTi6KmWuS5Zqbzy9wcHm/ZZPbZSe4A9QB0Y+t0r6hu+fc=",
    0x75: "01voHZZnnJciNJBrXWUdTUDc8vSdFtOcA9Y2fNYaM2VsYA9QB1ZAGH5AxLh1o=",
    0x76: "01q0xhYIVBOosokTZXI5rrRQLanwxvJfRg6J10euBeHeAA9QB25NryCJ56FEg=",
    0x77: "01cGcspFxf+0tBzRgtIzTs2OG+kyogY6zyQlfNIXywPhwA9QB3qd8TD4/SB9A=",
    0x78: "01H1TAHqqUcG440PSFKwXKYK+kHhn9joU5o7tHBkB0u/wA9QB4vcy3May3QLA=",
    0x79: "01bCP4mh5HmLNsAyJfJG1sqQCZtjNokXWw11FPivDTnHgA9QB5gpF3oQe3j5s=",
    0x7A: "019kSwdShtwXv+r4d8IIWrRxbc4L6AGkJEZ+x+mHo5poMA9QB64nrM/7i4FQI=",
    0x7B: "01U6j3KPT2bvarKbEIecq3G6xWc/Fm/gXfjTQ/NjT0WQEA9QB7OonDEpgQM+8=",
    0x7C: "01nNzBj1t6YY+SdxbMIeHq9bJMdgrBybLsjPRSsoX9eN8A9QB8hhFaK9myzdU=",
    0x7D: "01DftdebCDKLmd5vsmwybBzaidPd2u3hdC8qcXi1kmaW0A9QB9VSn1B/lIyoI=",
    0x7E: "01flBOFU42alWzyf2G9PSnJeTzpk7R7LBw7KgT3XbrdgMA9QB+EQaMiyrEQuI=",
    0x7F: "01PpuYfSRTklSsKKbbf4VagU5nG29toK2Y/7NgUDCbiT4A9QB/Tpp2KomLpJA=",
    0x80: "0158cgKIz5atlNHRyirx8mBcyDw3RzFJPr64iXE0T6XloA9QCA+4tm59SWpA8=",
    0x81: "01ZKHjcVdrWnBYqd/sw4z5YR7z3NqPC+b7ATXL0HtCcHQA9QCBlp+rL53FYag=",
    0x82: "01Zlotl4FXZYkPdT2TQVUaSDde+EYMxUQSGMqQreVc7mMA9QCCltEaggRnkek=",
    0x83: "01K6ESscADv3doOzAHEds24ME395Y+rSYJwVoIygiIRvMA9QCD1FkJmsblK60=",
    0x84: "01yKyhLCAFWcnHaG0j5z+rRqzdY1VK5v7gLOVSTbqGz4YA9QCE+1H6yftpZoQ=",
    0x85: "01gas60E44loqWfl7k8fllMiDSlr/QtY/5tsZIF7BW2F8A9QCFqtWLjJkGlf4=",
    0x86: "01BdIkAMF1tO1w9bnV2PMQEgcJpbsmRDce2J/6C+2dFSoA9QCGLhtKt/SRs9E=",
    0x87: "01CQPSJqJAUF30kUuEh15kDdZqfqta9p2GrPtILEH8W7UA9QCHWt1m7fCkCFs=",
    0x88: "01gC2k2HfcPXWPq/l/yySUaez0v0e13bl7nekBjscHmoUA9QCItcUSSpuoCJ0=",
    0x89: "01u8NIMScH94r/ZnP3NZ375e1bDwjrQyfOXyD8A2gYkm8A9QCJh7B9S+qNJfM=",
    0x8A: "01ZVWq8V6b0CYrP7yrJY6JOAP1kCh+FcqDmuco55SD5N8A9QCKfQYQBHRX0OA=",
    0x8B: "01b8gSU/+7/2sX1xCLT9E671g6Z+8BBfuDXFDBuwDLX1EA9QCLX2H4pkZ1X/0=",
    0x8C: "01eu5yUTis6NcpiA8aV93Kio1jo16exGiqUP+sNXKMwi8A9QCME1nwAMPTDqE=",
    0x8D: "01CpefxxckfjTlsGPep1dL49JPSG1p+2/0wrorJCFGxEoA9QCNrbCuRF+Gw3w=",
    0x8E: "01jHTYH8SnrwLQ/n9o81FojInhziuqpCqxNuyXeBi9SH0A9QCOtSkH9+ZdPTg=",
    0x8F: "01ldSMz2LdfT+X1IwImTmjZdPBRfVdqoogkMEWFBoP9YwA9QCPojaQF+qN5Y0=",
    0x90: "01iVPYi2AipJiBTdYeB2imBQggq0wr8yrsM5aTUmOIgCsA9QCQvaK+uSve+Cw=",
    0x91: "01s8AzxVVnElvjD7I9G3MFHYu46QEpZ8LAbOqPU3DiJwYA9QCR6nCRUogaWsE=",
    0x92: "01sgqbD6nsKDz8SawCanylLyqwtoFUeMsY2Y6FxEi4rP0A9QCSAP8Ivi0OzQk=",
    0x93: "01I9OeXKI+9aHkJNtpWJsQk2K9uB2N4owdDJdfgpl+2XkA9QCTJUNKxJ/fxfw=",
    0x94: "01mzK11OiK3zwYY9HtaGqYJJlKQl/LSzw6lw8Um8D2Z+cA9QCUDd4ywAsjKYY=",
    0x95: "01hXltaa9asjYP3hkerOLy4xOb5cdCeW6vxB7CTwgYXgoA9QCV/VPRdSVXr5c=",
    0x96: "013OcEZAcZcIYk+JAME6xdICjftyo+oVAEWPBrz7/VcL4A9QCWrSwFxs4BcJY=",
    0x97: "01V3LIsO0KSvTpBznfWlKHSC1wJ9/HeOCUflgq5xVw0p0A9QCXh4BjaJKZ20U=",
    0x98: "01zB/Xt78FCuFJalzTYkZxkfVRYSGsj1btny/yS64sadcA9QCY+Su3BQlDCoM=",
    0x99: "01BQiQXVCPBCe+KRgh0mTRtcIOjbz57ioHJyPDcWIPIf0A9QCZp4rR2gVJ3vc=",
    0x9A: "01HWhMtUXpxiqpXZX7pesmxjjidDlHz8DEpCRVouJYsXQA9QCaiic/44Av9Bc=",
    0x9B: "01AJq19ZS7yEp2G2qr9TachL67wGZCDzxAE7za+sD3W0AA9QCbtzd/JAPGqsg=",
    0x9C: "01F69vVcywbPCj6R5Mt3mvureFySYOM/HaS+2A5bXCEnkA9QCcV69bTqe+Eqk=",
    0x9D: "01Gb/0Qkgc+M4XBL2QT+mJoJ/GTlyjE/JwJLUJdBIzGSsA9QCd0MEPjzR7XlA=",
    0x9E: "01s+j8COe6AiH3BPA7x5l2cUoPouaLhYPa4VvFQHwhz3MA9QCeAlTyk+rZ7oA=",
    0x9F: "013c5xF7tG2debbOl32PczFukhxK6bU2jM0qf9LZf1lk4A9QCfqP6MZObsXGA=",
    0xA0: "01riKSrZnDwxegohx1gc0SCsaJhwpdx74kIAHBv2efRD8A9QCgSkh+gg6gu9E=",
    0xA1: "01XB89nLrHVf3Iz3HhDwrqAUiHQM2snAzqLAP5z3IoiaIA9QChXd9JguYlpFo=",
    0xA2: "01wrI6aMFZ43DQ3LwvLA83ALrf7nFFoeBUwu6eqYzse3MA9QCivyxUTWjoH60=",
    0xA3: "01cD8sTsxwmzQ1ELjRb7+zIJACVqaj3WHvVk1Ydoz4r5UA9QCjVhTVuu6YAv0=",
    0xA4: "01RN7C/CPM4rkDeovve5d/grvKErZ/5HarMVgdEgLYD7YA9QCkJeJzSUdZZkY=",
    0xA5: "011VhX4jxoAL2SDDMRdUHBg0EIVgcIZnS/yzCGFnkvqMoA9QClBO1b8iVccgQ=",
    0xA6: "01e4B+QtZ7YUOKNpJjxCsO5dtipbyDLJONW4m3Ls2GsGQA9QCmeBNt8oUBewY=",
    0xA7: "01DYHzvaGq3g9RS1NV4ZwUa/4C103i6QYtg3XrimDFF8oA9QCnJia6cFvwzq0=",
    0xA8: "01mUOat+37IaeZXMYWqFCX+SqFo2ELynfxhXHiwTubXVYA9QCoi6JsR8kylHI=",
    0xA9: "0187WM0Zhkzob6pXoZy5l+tq4NlPEQRdUCTyYvWePmF2QA9QCpr8KHT6maVbM=",
    0xAA: "01lKWHZr9hIDoleSc38CnYqQBU/Yugu0Pg3UTGhg6maKkA9QCqZtOj3CFdXxA=",
    0xAB: "01uxKwG+y5t7A4AYwFEy6s0NA6OE8tld/1sso58Jlx+b8A9QCry9CYW/f8R6U=",
    0xAC: "01Sa5i99M9SV7H7Xz7ysfAv1s5A9LDbRbMErDgHcMYwU8A9QCsgb2lhJCIr8Q=",
    0xAD: "01jOXZuEUaJAdaIfJROR1+dvSL3VRTBOiQfV7GqrCSnucA9QCtUyQHM70Eo+Y=",
    0xAE: "01rxGZDeSyL42+2k661bUuTEWDI2MgpMx+sjI9PZ5K3E0A9QCuDEitB7CMTgM=",
    0xAF: "010DZwcs6j0cLupnE3ktse6z72zxmjRp0BwfPkBCNapDoA9QCv8gL1rvTNKmw=",
    0xB0: "01o73R4AYeSA0O4LtvnjBVVytcZG7UJQEvyKIQt2+ky6QA9QCwdBu77BiC7Zo=",
    0xB1: "0119d+NMZAl4nKS7GD6TvDEh6pNcYsrWxnAvZB9jdUqJYA9QCxyjS9UdtX74A=",
    0xB2: "01ZKnKg4MmdqiZungTh9Net2y4pj9oAeFnuVtUELqfLUEA9QCyKTwLV6SrUdk=",
    0xB3: "01iiSAsDvuGbdq8aX/5Uc+luUo6N26ceL2Gnskw+vk7AkA9QCz7/8J7JELM/Q=",
    0xB4: "01wEybLBO2TtNUx8YlTlh5tr3S47qhZlW7xxaIMmUk3hQA9QC04Efks8AIxTU=",
    0xB5: "01oQxz5LFu5n6M0Q7bjZKKtQlbmiFw54dPy5BftRRiiv0A9QC1yYozwSU9mHg=",
    0xB6: "01Vk74q3+HDhcUeq4ivWSz+WJC2cGtKrLs1Z75YgQ9wQsA9QC2d6hrVmj/Lr8=",
    0xB7: "019obQ4g0eJozErHKiJez1ucNuwIeFyFYQnSXalcsaFecA9QC3yuKmyKrCRz0=",
    0xB8: "01ShQSAxcy/62WC9Dmok9cWqWe76RkV+PlTN51KXvXsuIA9QC4quJSy9aJ30g=",
    0xB9: "01Wc19Q0Cd+IxvNVuRSYmAWz43Mug6X7fE+ti25EFqy1gA9QC51VJACEewbX0=",
    0xBA: "01KMpiG9A7T1Yc47RMaOHnmnAAt9LPTvBlKsRqoDlwACwA9QC6GgmG0lItkPQ=",
    0xBB: "01mrrSn51GVH+hGhjze+IZRGLPRNjS9PjiBFLaBRHGbyAA9QC7sPcA4qy/8PQ=",
    0xBC: "01eax3unXuamELKDUm63fP3tmGLggREvU/7q+7/+y96vMA9QC8sGbFvNPgRUI=",
    0xBD: "01x4FrivUyjapkWhI5YlaOfzPdjDTvzekgYOk/M9719Q4A9QC9S4DKyhH5f0k=",
    0xBE: "0104ZdwCBjjBdzIBVb39tu9yF72QpmQ3hSfnmQEjB3jBEA9QC+2UWa+PieQ3E=",
    0xBF: "01XbLmZjejHJ52HGAuOXWgiv+X2cEBRUklZ1o456iGpg8A9QC/1d4IOlkOc+U=",
    0xC0: "01uUemY6wT6n7eQgJsBP18yZwDXKg6XZmtZt8lr6sKYwkA9QDAGOFxtDbun04=",
    0xC1: "01eBjY3cxEFHx6lRK7dkbU1NzaJ8ilmeqZw+CFuegWjl4A9QDBtNtsW8jynqk=",
    0xC2: "01cxW1pFo/YnUs99C9B1sU+6QDb+SlWHhaoI5XSYZHRSUA9QDCxpcKztCUbPs=",
    0xC3: "01tpxvOCMoZnRZwCx+C6GmvCEdCFcWz/odNEBIFngvVq4A9QDD2AMqsDogPaA=",
    0xC4: "010BuvdF60cpb0eV7c7xvHztT6xeXUlqAktRj/OX8heRQA9QDEFa+Ow3uHfrg=",
    0xC5: "017AnNA39T2mQXWclaxS8jQjoy1vCdeJBUlfXYpwSjveUA9QDFAGjKi0BKoP0=",
    0xC6: "01U9Vs6MMYUZnjgrHdvTyXkPk09rOeSqTdhVvLgK9qyRgA9QDGowPx/4ouy2I=",
    0xC7: "01BhEwlLeznoQcAvdfhXG5zP9DDzaA7nHFY0YsDx9VptEA9QDHr7Hrlfjjy1Q=",
    0xC8: "01osA2G/JKPjtre3F/aLqzsV/5wFCWkMBlUTXPYQALpXwA9QDIsmjQVVIJOBY=",
    0xC9: "01APTDRLesYQF8jF3T1e0mJviyaE8ZQbLhLHf0iSnNNL4A9QDJd9WrIOBCmPg=",
    0xCA: "019ClfWtfCPPexu4jZCn8E3UJJUtcrO6XJUcJ8ot7/jOUA9QDKUP/cOj+9DwI=",
    0xCB: "01GfnLcM56Ogqo5kuKna0knG4vHu01Aweb8o3shNk4kdwA9QDLxEJszADx5ro=",
    0xCC: "01bzNCY11gQ4wfybfRow74waIzmSleHIQi9LUdc6aoBIQA9QDMdd6raTvQJJg=",
    0xCD: "01XEqW2DcTnCIRuL39aj7AHJ15Xb/tSN+4obrNT2XBYB4A9QDNM2DxWRj3Vd4=",
    0xCE: "0174wqqOXMCpSOnU2Lng9DysTI6XRgJOOzrmlpRFrW99cA9QDO2vLloq4qlrM=",
    0xCF: "01F0kT+HUsHgdZMaPTiUA5VuiFb32J97l4CGnoLALf0noA9QDPdWV0HPcrZSg=",
    0xD0: "01QAdMAu67r9Ts1CXACDVb4pi77bZ/5sCL218IKdkR+KsA9QDQ5ho2P+myrZI=",
    0xD1: "01aIpLWofG15lhCdRkq4OVxFxyDNlY9AQe+Sxw8Ez1wgIA9QDRz2SgGRA9bpo=",
    0xD2: "01cTN6mM8lLn+2JhXnXzFkf+1y6/i+AV2qgqj849dsZYoA9QDSISg4guxlros=",
    0xD3: "010KSweNK36uIq5u2XnKdN1f6zJST6KfEV2eRLUj2gW+kA9QDTe+VN+pQvVN8=",
    0xD4: "01BjPiWcWMFNEWVwMHRwRsU6FxYOhN/5s9C+s3hUbXuVsA9QDUqI8FVMKWTu4=",
    0xD5: "01ZJxP8ch2/jFRfP7ZMAyVB3mOz0kmXHaa/49jr5uhyQIA9QDVV9YF9uwGoPQ=",
    0xD6: "01aXkRq1sPci96K7nx96eG3EG36OhHrRjXk50YdMa8jRUA9QDWTFthm8bz9lc=",
    0xD7: "010+SdM9+RFyzJF5EH0Y03lh+bZ8dkj575Q+1/rVpghEgA9QDXI4SCAokB1Ws=",
    0xD8: "01LsX7y8EDu7e32p9kBD6/35HaTvCgU3j8DI291q9w+V4A9QDYOHLDSGt/p5E=",
    0xD9: "01HerUqqMVjy7ElbhfSGhF7oQ2CwH4kSyKeYn+984GbZUA9QDZmZ12guW4nEc=",
    0xDA: "01sq9ZTyg/uamwZKtb6G4pXbLU3imlV64GtEYVcIwc19EA9QDaCcPxBW8FT4A=",
    0xDB: "01I4w5qZWAFfel8uJrpaB+0XGhNMJhlPLk2IOh2rPNSUEA9QDbGbAYVmT/74o=",
    0xDC: "01W+jmCQJlvcLhAY3YPzKSflTjvrFr1G1tH/wWBeVL62IA9QDcAbVWB36nbx4=",
    0xDD: "01XhynrWGgIS9v9bkwGxADdlSQBVVr0ezOvd3W6N/AS7cA9QDd8nrXhEMsgDc=",
    0xDE: "01zTyvv9YtVss0eSJ6FACF6Nc+u+mL29mu6yYirmFRKi8A9QDe0AGAmR4fLcY=",
    0xDF: "019+nob9ZiHwaRJU6Cx+lBBHufg+AJL6qe0u4cR0KHalwA9QDfFAilx9Vvb/w=",
    0xE0: "01uYEF+dBwc+cT3ocldEYLoBMBL93xVBEXgMwW3pehDh0A9QDgZ0Xh+zTzW7o=",
    0xE1: "01ZDThF9vrJybP/+a6YDg7zalHxdbcmL4M9XYCw29QemAA9QDhx7nDSnj85PM=",
    0xE2: "01JclXHp1GSrbwjxLEZ+n0oJvoN3X9hKC/DmT9aJdvDdwA9QDiq+2YBSKAEkU=",
    0xE3: "01ixep85GehkH5t6XKCR9i1joBJaFl5Sb36Rqgm8SXWxYA9QDj2mipDaGl0Yo=",
    0xE4: "01WsQ/mFQL063c/lPLeB2zL1wD66E/YCfxSulEZ9hjfW4A9QDkp/as3+IlWXQ=",
    0xE5: "01zcT3cwWBMMwi8qFKwsj9d7W9B1daoBDE6bkAm6WzA3MA9QDlbjOEmKaqlLs=",
    0xE6: "01ED4oUlKfRcWnXeYsLtDILAy4Z1ouLwz6TOiHfDt6dTYA9QDmQQQ5XMOgMeY=",
    0xE7: "015eZT2Fd8WyEvy0fDsYAob5E+Po2r8/kxvTAadGgbbHkA9QDn1rB0N8LDUds=",
    0xE8: "01uEsKPiaL1JNI9CNydCzERDKuQ79D+HpW5RmBieRulrcA9QDoe+8R0cR+QsE=",
    0xE9: "01df5o1LcRC82Td/QyZMJlMQTh4jc85FYQPYjcIGCnmMoA9QDpxGnG1V/A6vg=",
    0xEA: "015TBq4z+cosSY48N8GppV3Lu1DMSTWj88bM0jjjKOIlYA9QDqKlZln2uOz8w=",
    0xEB: "01bviPVwO2fDKdPpOFw5RHcTLyJHof6QR/zBwp0NB4MJsA9QDrctkpOSvXht0=",
    0xEC: "01vKvPMw/EM86zYKsq9BZ8QmBJfHtbNUDhutGuR7JNh8UA9QDs2WF4UpDxTnA=",
    0xED: "01cdSR7LduuhIk+zzyy4Th1XEfLfXhJMomGwkVs0x0PYkA9QDtWRjqUN4lcZY=",
    0xEE: "01uVUomAEtq1qddKAcG8aqK+AcAZamcUMLNvc37/8rY8oA9QDu7LVPSX0VBNU=",
    0xEF: "01a1czIEm3yGyYo0IJAlbUq/1QVDgHVBiJZTSkfGyLqqkA9QDvbmmByRUO3SE=",
    0xF0: "01oCBLAlH/QbSb4/1TWRgiLWfyc3Yy/7qWIJ2tM+KuME8A9QDwIqj782i9/UI=",
    0xF1: "01vU8CaeDWeMZDAFXBbKaa/K8QcuCkeL3K3gchOjL42AUA9QDxCk1T7SkbABQ=",
    0xF2: "01jD0Qsf8o2RccMeMxzSZbKP/tbPlI+cS3WDXiLoVg0C0A9QDyvBsFxZc0A/0=",
    0xF3: "01Ak8k1QkhzYljBn2s3e94s9ygNT/JgDqpcS3HAfTECS8A9QDzHcLPRVsfvIA=",
    0xF4: "01ELuR0V3hEUolnluml7M0hreCE108wWovyNFWnLqPi+kA9QD0mYpSp1k5vY0=",
    0xF5: "01FgFvAwpvHIyGSgMYVsdOz/vOIsR4eS/FL6OAxRYxtsUA9QD1y79DhQv/AzU=",
    0xF6: "01Eo/ZMNSg6X52WhJm6rOYjq6ErPbxyfexTfeJhCnHpWEA9QD22ztm8EYQCrc=",
    0xF7: "01g+nXfw49hCpE4Vx9TUDgj/vuJjW60FxU2CZCBUVoGocA9QD3sVqGXRgJFW4=",
    0xF8: "015HiHfJHq8s3QSQMdnlVPU/P6CAlKD7ujZ7VF/OzXuigA9QD4WX48ixdxKfA=",
    0xF9: "01q7iOmQhpf03wMdb/Dld9l/X3CdOpotqrATEOqHTDg9IA9QD5NJmIF54BgK8=",
    0xFA: "01s/mtJ9+u6EvImIs8fmg1FZpAboyfZFWJmiFtYaD+zqEA9QD6YiTsvrUxtF8=",
    0xFB: "01pWPbxhRwXYv20S0sqytFVQRdCii1Bth9ElqrEyHZo4AA9QD7Ka/VJ53mBxc=",
    0xFC: "01t70j5dCz8OtNP2suXH9jX4By923A8qZ/HlfIoKJyIscA9QD8QBFD+j0DNc4=",
    0xFD: "01HQpS7K+PhuBN1Y8x2r6o297fv8RJ7oOO4gCWp/LoRqMA9QD90Mzd2IGm3Dg=",
    0xFE: "01zO5Wjn2SVYsTRUVBjTxZQBmQZF6aHLzod82ddiHJkCgA9QD+bWRPEgaXH9Y=",
    0xFF: "01tRpkm8gqDi4NkXtkog3jClp79tHI1/tKjAwTgMvE37IA9QD/pwJnkexTRWY=",
}

SBOX: List[int] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

RCON: List[int] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1B, 0x36,
]


@dataclass
class PasswordRecord:
    secret: bytes
    min_seed: int
    algo_id: int


def parse_password_blob(blob: str) -> PasswordRecord:
    """Validate and unpack a 62-char blob into its secret, thresholds, and id."""
    if len(blob) < 62:
        raise ValueError("Password blob too short; expect prefix plus 60 chars")
    prefix = blob[:2]
    if prefix not in {"01", "03"}:
        raise ValueError("Unsupported password prefix (expected '01' or '03')")
    payload = blob[2:]
    if len(payload) != 60:
        raise ValueError("Password payload must be exactly 60 Base64 characters")
    raw = base64.b64decode(payload, validate=True)
    if len(raw) != 44:
        raise ValueError("Decoded payload must be 44 bytes")
    secret = raw[:32]
    min_seed = int.from_bytes(raw[32:34], "big")
    algo_id = int.from_bytes(raw[34:36], "big")
    digest = hashlib.sha256(raw[:36]).digest()[:8]
    if digest != raw[36:44]:
        raise ValueError("Digest mismatch – blob is not authentic")
    return PasswordRecord(secret=secret, min_seed=min_seed, algo_id=algo_id)


def bytes_to_state(block: Sequence[int]) -> List[List[int]]:
    """Convert a 16-byte block into the 4x4 matrix AES uses internally."""
    return [[block[row + 4 * col] for col in range(4)] for row in range(4)]


def state_to_bytes(state: Sequence[Sequence[int]]) -> bytes:
    """Collapse the AES state matrix back into a bytes object."""
    out = bytearray(16)
    for row in range(4):
        for col in range(4):
            out[row + 4 * col] = state[row][col]
    return bytes(out)


def sub_bytes(state: List[List[int]]) -> None:
    """Apply the S-box substitution to every byte of the state in place."""
    for row in range(4):
        for col in range(4):
            state[row][col] = SBOX[state[row][col]]


def shift_rows(state: List[List[int]]) -> None:
    """Rotate each row of the state by its row index (AES rule)."""
    for row in range(1, 4):
        state[row] = state[row][row:] + state[row][:row]


def xtime(value: int) -> int:
    """Multiply by x in GF(2^8)."""
    value <<= 1
    if value & 0x100:
        value ^= 0x11B
    return value & 0xFF


def gf_mul(a: int, b: int) -> int:
    """Multiply two GF(2^8) values using the xtime helper."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result


def mix_single_column(col: MutableMapping[int, int] | List[int]) -> None:
    """Mix one AES column in place."""
    a0, a1, a2, a3 = col
    col[0] = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3
    col[1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3
    col[2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3)
    col[3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2)


def mix_columns(state: List[List[int]]) -> None:
    """Run MixColumns on the whole AES state."""
    for col in range(4):
        column = [state[row][col] for row in range(4)]
        mix_single_column(column)
        for row in range(4):
            state[row][col] = column[row]


def add_round_key(state: List[List[int]], round_key: Sequence[int]) -> None:
    """XOR the given round key into the AES state."""
    for col in range(4):
        for row in range(4):
            state[row][col] ^= round_key[row + 4 * col]


def rot_word(word: List[int]) -> List[int]:
    """Rotate a 4-byte word left by one byte."""
    return word[1:] + word[:1]


def sub_word(word: List[int]) -> List[int]:
    """Apply S-box to each byte in a key schedule word."""
    return [SBOX[b] for b in word]


def expand_key(key: bytes) -> List[List[int]]:
    """Derive the 11 round keys required for AES-128."""
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes long")
    words: List[List[int]] = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = words[i - 1].copy()
        if i % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[i // 4]
        new_word = [(words[i - 4][j] ^ temp[j]) & 0xFF for j in range(4)]
        words.append(new_word)
    round_keys: List[List[int]] = []
    for i in range(0, 44, 4):
        round_keys.append(sum((words[i + j] for j in range(4)), []))
    return round_keys


def aes_encrypt_block(key: bytes, block: bytes) -> bytes:
    """Encrypt a single 16-byte block with AES-128 (no padding)."""
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")
    round_keys = expand_key(key)
    state = bytes_to_state(block)
    add_round_key(state, round_keys[0])
    for rnd in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[rnd])
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[10])
    return state_to_bytes(state)


def run_hash_chain(secret: bytes, iterations: int) -> bytes:
    """Repeat SHA-256 hashing `iterations` times, returning the final digest."""
    digest = secret
    for _ in range(iterations):
        digest = hashlib.sha256(digest).digest()
    return digest


def derive_key_from_blob(blob: str, seed: bytes, algo: int) -> tuple[bytes, int, bytes]:
    """Derive the 5-byte MAC from a specific blob and seed."""
    record = parse_password_blob(blob)
    if algo != record.algo_id:
        raise ValueError(f"Algorithm mismatch: blob expects {record.algo_id}, got {algo}")
    if len(seed) != 5:
        raise ValueError("Seed must be exactly 5 bytes")
    seed_tail = seed[4]
    max_seed = 255 - seed_tail
    if record.min_seed > max_seed:
        raise ValueError("Seed is not allowed by the blob's min_seed constraint")
    iterations = max_seed - record.min_seed
    digest = run_hash_chain(record.secret, iterations)
    aes_key = digest[:16]
    block = bytearray([0xFF] * 16)
    block[11:16] = seed
    mac = aes_encrypt_block(aes_key, bytes(block))[:5]
    return mac, iterations, aes_key


def derive_key_from_algo(algo: int, seed: bytes, password_map: Mapping[int, str] | None = None
                          ) -> tuple[bytes, int, bytes]:
    """Look up the blob for `algo` and run the derivation pipeline."""
    if password_map is None:
        password_map = PASSWORD_MAP
    blob = password_map.get(algo)
    if not blob:
        raise ValueError(f"No password blob registered for algorithm {algo}")
    return derive_key_from_blob(blob, seed, algo)
