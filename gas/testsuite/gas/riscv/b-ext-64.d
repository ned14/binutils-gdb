#as: -march=rv64i_zba_zbb_zbc_zbs
#source: b-ext-64.s
#objdump: -d

.*:[ 	]+file format .*


Disassembly of section .text:

0+000 <target>:
[ 	]+0:[ 	]+60051513[ 	]+clz[ 	]+a0,a0
[ 	]+4:[ 	]+60151513[ 	]+ctz[ 	]+a0,a0
[ 	]+8:[ 	]+60251513[ 	]+cpop[ 	]+a0,a0
[ 	]+c:[ 	]+0ac5c533[ 	]+min[ 	]+a0,a1,a2
[ 	]+10:[ 	]+0ac5d533[ 	]+minu[ 	]+a0,a1,a2
[ 	]+14:[ 	]+0ac5e533[ 	]+max[ 	]+a0,a1,a2
[ 	]+18:[ 	]+0ac5f533[ 	]+maxu[ 	]+a0,a1,a2
[ 	]+1c:[ 	]+60451513[ 	]+sext.b[ 	]+a0,a0
[ 	]+20:[ 	]+60551513[ 	]+sext.h[ 	]+a0,a0
[ 	]+24:[ 	]+0805453b[ 	]+zext.h[ 	]+a0,a0
[ 	]+28:[ 	]+40c5f533[ 	]+andn[ 	]+a0,a1,a2
[ 	]+2c:[ 	]+40c5e533[ 	]+orn[ 	]+a0,a1,a2
[ 	]+30:[ 	]+40c5c533[ 	]+xnor[ 	]+a0,a1,a2
[ 	]+34:[ 	]+60c59533[ 	]+rol[ 	]+a0,a1,a2
[ 	]+38:[ 	]+60c5d533[ 	]+ror[ 	]+a0,a1,a2
[ 	]+3c:[ 	]+6025d513[ 	]+rori[ 	]+a0,a1,0x2
[ 	]+40:[ 	]+6025d513[ 	]+rori[ 	]+a0,a1,0x2
[ 	]+44:[ 	]+6b855513[ 	]+rev8[ 	]+a0,a0
[ 	]+48:[ 	]+28755513[ 	]+orc.b[ 	]+a0,a0
[ 	]+4c:[ 	]+20c5a533[ 	]+sh1add[ 	]+a0,a1,a2
[ 	]+50:[ 	]+20c5c533[ 	]+sh2add[ 	]+a0,a1,a2
[ 	]+54:[ 	]+20c5e533[ 	]+sh3add[ 	]+a0,a1,a2
[ 	]+58:[ 	]+0ac59533[ 	]+clmul[ 	]+a0,a1,a2
[ 	]+5c:[ 	]+0ac5b533[ 	]+clmulh[ 	]+a0,a1,a2
[ 	]+60:[ 	]+0ac5a533[ 	]+clmulr[ 	]+a0,a1,a2
[ 	]+64:[ 	]+6005151b[ 	]+clzw[ 	]+a0,a0
[ 	]+68:[ 	]+6015151b[ 	]+ctzw[ 	]+a0,a0
[ 	]+6c:[ 	]+6025151b[ 	]+cpopw[ 	]+a0,a0
[ 	]+70:[ 	]+60c5953b[ 	]+rolw[ 	]+a0,a1,a2
[ 	]+74:[ 	]+60c5d53b[ 	]+rorw[ 	]+a0,a1,a2
[ 	]+78:[ 	]+6025d51b[ 	]+roriw[ 	]+a0,a1,0x2
[ 	]+7c:[ 	]+6025d51b[ 	]+roriw[ 	]+a0,a1,0x2
[ 	]+80:[ 	]+20c5a53b[ 	]+sh1add.uw[ 	]+a0,a1,a2
[ 	]+84:[ 	]+20c5c53b[ 	]+sh2add.uw[ 	]+a0,a1,a2
[ 	]+88:[ 	]+20c5e53b[ 	]+sh3add.uw[ 	]+a0,a1,a2
[ 	]+8c:[ 	]+08c5853b[ 	]+add.uw[ 	]+a0,a1,a2
[ 	]+90:[ 	]+0805853b[ 	]+zext.w[ 	]+a0,a1
[ 	]+94:[ 	]+0825951b[ 	]+slli.uw[ 	]+a0,a1,0x2
[ 	]+[0-9a-f]+:[ 	]+48059513[ 	]+bclri[ 	]+a0,a1,0x0
[ 	]+[0-9a-f]+:[ 	]+49f59513[ 	]+bclri[ 	]+a0,a1,0x1f
[ 	]+[0-9a-f]+:[ 	]+28059513[ 	]+bseti[ 	]+a0,a1,0x0
[ 	]+[0-9a-f]+:[ 	]+29f59513[ 	]+bseti[ 	]+a0,a1,0x1f
[ 	]+[0-9a-f]+:[ 	]+68059513[ 	]+binvi[ 	]+a0,a1,0x0
[ 	]+[0-9a-f]+:[ 	]+69f59513[ 	]+binvi[ 	]+a0,a1,0x1f
[ 	]+[0-9a-f]+:[ 	]+4805d513[ 	]+bexti[ 	]+a0,a1,0x0
[ 	]+[0-9a-f]+:[ 	]+49f5d513[ 	]+bexti[ 	]+a0,a1,0x1f
[ 	]+[0-9a-f]+:[ 	]+4bf59513[ 	]+bclri[ 	]+a0,a1,0x3f
[ 	]+[0-9a-f]+:[ 	]+2bf59513[ 	]+bseti[ 	]+a0,a1,0x3f
[ 	]+[0-9a-f]+:[ 	]+6bf59513[ 	]+binvi[ 	]+a0,a1,0x3f
[ 	]+[0-9a-f]+:[ 	]+4bf5d513[ 	]+bexti[ 	]+a0,a1,0x3f
[ 	]+[0-9a-f]+:[ 	]+48c59533[ 	]+bclr[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+28c59533[ 	]+bset[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+68c59533[ 	]+binv[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+48c5d533[ 	]+bext[ 	]+a0,a1,a2
