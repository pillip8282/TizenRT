######################################################################
#
# link: https://www.adacore.com/gems/gem-119-gdb-scripting-part-1
#
# Enable CONFIG_FRAME_POINTER at Debug options in Kconfig
######################################################################

dir ../framework/
dir drivers/
dir ../lib/libc/
dir ../apps/examples/security_test/
dir fs/
dir kernel/

set history save on
set history filename ./.gdb-history
set history size 1000

set height 0
set width 0

define load_artik
  file ../build/output/bin/tinyara
  tar remote :3333
end

define print_task
  set $list = (struct tcb_s*)$arg0
  printf "%-3d", $list->pid
  printf "%-12s", $list->name
  if $arg1 == 0
	printf "\tRUNNING"
  end
  if $arg1 == 1
	printf "\tWAITSEM"
  end
  if $arg1 == 2
	printf "\tWAITSIG"
  end
  if $arg1 == 3
	printf "\tMQNEMPTY"
  end
  if $arg1 == 4
	printf "\tMQNFULL"
  end
  if $arg1 == 5
	printf "\tWAITFILL"
  end
  if $arg1 == 6
	printf "\tINACTIVE"
  end

  printf "\t%d", $list->adj_stack_size
  printf "\t0x%08x", $list->stack_alloc_ptr
  printf "\t0x%08x", $list->adj_stack_ptr
  #printf "\t0x%08x", $list->xcp->saved_pc
  printf "\t"
  if $arg1 == 0
	info symbol $pc
  else
	info symbol $list->xcp->regs[15]
  end
  #printf "\n"
end

define find_frame
  set $task = $arg0
  set $check = 0
  set $list = (struct tcb_s*)g_readytorun.head
  while $list != 0
	if $list == $task
      # running task
      set $check = 1
	end
	set $list = $list->flink
  end

  if $check == 1
	set $task_fp = $r11
	set $task_sp = $r13
  end
  if $check == 0
	set $task_fp = $task.xcp.regs[11]
	set $task_sp = $task.xcp.regs[13]
  end
  set $task_sp_top = $task->adj_stack_ptr
  set $id = 0
  while $task_fp < $task_sp_top && $task_fp > $task_sp
	set $task_pc = *($task_fp - 4)
	printf "#%d\t0x%08x in ", $id, $task_pc
	info symbol $task_pc
	set $task_fp = *($task_fp - 12)
	set $id = $id + 1
  end
end


define show_frame
  set $num_tasks = sizeof(g_pidhash)/sizeof(struct pidhash_s)
  set $idx = 0
  set $check = 0
  while $idx < $num_tasks
	set $tmp_task = g_pidhash[$idx].tcb
	if $tmp_task.pid == $arg0
	  set $task = (struct tcb_s *)g_pidhash[$arg0].tcb
	  set $check = 1
	  set $idx = $num_tasks
	end
	set $idx = $idx + 1
  end

  if $check != 1
	printf "Can't find a matched task\n"
  else
	find_frame $task
  end
end


define show_task
  printf "PID\t| Name\t| State\t| ST SIZE\t| ST END\t| ST START\t| PC\n"
  set $list = (struct tcb_s*)g_readytorun.head
  while $list != 0
	print_task $list 0
	set $list = $list->flink
  end

  set $list = (struct tcb_s*)g_waitingforsemaphore
  while $list != 0
	print_task $list 1
	set $list = $list->flink
  end

  set $list = (struct tcb_s*)g_waitingforsignal.head
  while $list != 0
	print_task $list 2
	set $list = $list->flink
  end

  set $list = (struct tcb_s*)g_waitingformqnotempty.head
  while $list != 0
	print_task $list 3
	set $list = $list->flink
  end

  set $list = (struct tcb_s*)g_waitingformqnotfull.head
  while $list != 0
	print_task $list 4
	set $list = $list->flink
  end

  set $list = (struct tcb_s*)g_waitingforfill.head
  while $list != 0
	print_task $list 5
	set $list = $list->flink
  end

  set $list = (struct tcb_s*)g_inactivetasks.head
  while $list != 0
	print_task $list 6
	set $list = $list->flink
  end
end


define reset_artik
  printf "Reset artik053"
  monitor reset halt
  monitor cortex_r4 maskisr on
end


####################################################################################################################

define show_frame_origin
  set $task = (struct tcb_s *)g_pidhash[$arg0].tcb
  set $stack_start = $task->xcp->regs[13]
  set $stack_end = $task->adj_stack_ptr
  set $idx = 0
  #printf "stack start = %x, %x\n", $stack_start, $stack_end
  while $stack_start < $stack_end
	#printf "%x %x\n", $stack_start, *($stack_start)
	if *($stack_start) >= 0x040c8020 && *($stack_start) <= 0x0425d52c
      #printf "%x %x\n", $stack_start, *($stack_start)
      printf "#%d 0x%08x\t0x%08x\t", $idx, *($stack_start), $stack_start
      info symbol *($stack_start)
      set $idx = $idx + 1
	end
	set $stack_start = $stack_start + 4
  end
end

define show_frame_origin
  set $idx = $arg0
  set $task = (struct tcb_s *)g_pidhash[$idx].tcb

  set $tmp_r0   =   $r0
  set $tmp_r1   =   $r1
  set $tmp_r2   =   $r2
  set $tmp_r3   =   $r3
  set $tmp_r4   =   $r4
  set $tmp_r5   =   $r5
  set $tmp_r6   =   $r6
  set $tmp_r7   =   $r7
  set $tmp_r8   =   $r8
  set $tmp_r9   =   $r9
  set $tmp_r10  =   $r10
  set $tmp_r11  =   $r11
  set $tmp_r12  =   $r12
  set $tmp_sp   =   $sp
  set $tmp_lr   =   $lr
  set $tmp_pc   =   $pc
  set $tmp_cpsr =   $cpsr

  set $r0   = $task->xcp->regs[0]
  set $r1   = $task->xcp->regs[1]
  set $r2   = $task->xcp->regs[2]
  set $r3   = $task->xcp->regs[3]
  set $r4   = $task->xcp->regs[4]
  set $r5   = $task->xcp->regs[5]
  set $r6   = $task->xcp->regs[6]
  set $r7   = $task->xcp->regs[7]
  set $r8   = $task->xcp->regs[8]
  set $r9   = $task->xcp->regs[9]
  set $r10  = $task->xcp->regs[10]
  set $r11  = $task->xcp->regs[11]
  set $r12  = $task->xcp->regs[12]
  set $sp   = $task->xcp->regs[13]
  set $lr   = $task->xcp->regs[14]
  set $pc   = $task->xcp->regs[15]
  set $cpsr = $task->xcp->regs[16]

  info all-registers
  bt full

  set $r0   = $tmp_r0
  set $r1   = $tmp_r1
  set $r2   = $tmp_r2
  set $r3   = $tmp_r3
  set $r4   = $tmp_r4
  set $r5   = $tmp_r5
  set $r6   = $tmp_r6
  set $r7   = $tmp_r7
  set $r8   = $tmp_r8
  set $r9   = $tmp_r9
  set $r10  = $tmp_r10
  set $r11  = $tmp_r11
  set $r12  = $tmp_r12
  set $sp   = $tmp_sp
  set $lr   = $tmp_lr
  set $pc   = $tmp_pc
  set $cpsr = $tmp_cpsr
end
