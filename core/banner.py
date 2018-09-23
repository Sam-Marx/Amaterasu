#coding: utf-8
#!/usr/bin/python3

from huepy import *
import os

def banner(versao):

	print('''\n
	   /-                                          -/  
	  /m/                                        /m/  
	  -NNs`                                    `sNN:  
	  .NNmh.                /+:               .hmNN.  
	  `mN-/d:              `yyo              :d/.Nm`  
	   dm` `o+             `yy+             +o` `md   
	   hd `: .+`           `yy/           `+. :` dh   
	   sh  -y. -`          `yy:          `. .y-  yy   
	  .os ` -do`           `yy-           `od-   so.  
	  yy+ `y--sy:          `yy.          :ys-   `+yh  
	/`y+:  ..              :yy-                +s:+y./
	:/o                 `:ss::oo-              .`  o/:
	                   /ss:    -os:                   
	 `-..`             /y/      +y+                   
	  `:syysoo+//:-.`   +y:    +y+     ``.-::/++o+:`  
	     syyhddhhhyys-   oy:  +y+  `/syyyyyyyyys.     
	    `syyyyohNNmdyy/` `oy-+y+  .syhmNNNddyyys      
	    `yyyys:`./+oyyys. `syy+  /yhmmhyo.`oyyyy`     
	     `-:+oss+.     `-` -ys `::-.`   .+syso+:`     
	           `-::.`      .y+       `:++:-`          
	                       `y/      ``                
	                        s:                        
	              `-        o.        .               
	               +-       +`       -.               
	               `h.      /       .o                
	                /h`     -      `h.                
	                 hy            ss                 
	                 :Ns          +m.                 
	                  yNy-:yyys:`/mo                  
	                   -omh//++hds/`                  
	                      :sdy+.
	''' + '''
		{}
		{}
		{}
	'''.format(bold(red('AMATERASU')), bold(purple('PENETRATION TESTING FRAMEWORK')), 'v' + versao))
