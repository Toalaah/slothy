start:
	add rax, rsp           // RR
	add rax,  0x0fafafaf   // RI
	add rax, -0x0fafafaf   // RI
	add rax,  10           // RI
	add rax, -10           // RI
	add rax, [ rsp ]       // RM
	add rax, [ rsp + 0x80 ]             // RM + disp
	add rax, [ rsp - 0x80 ]             // RM - disp
	add rax, [ rsp + 4 * rax ]          // RM + offset
	add rax, [ rsp + 4 * rax + 0x80 ]   // RM + offset + disp
	add rax, [ rsp + 4 * rax - 0x80 ]   // RM + offset - disp
end:
