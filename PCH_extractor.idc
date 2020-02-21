/*
IDA Pro 6.1 Script
Extract class hierarchy of polymorphic classes
from binaries compiled with g++ -std=c++11 -c -o run test1.cpp
on Debian GNU/Linux

Karampinakis Emmanouil July 2015

Distributed computing systems Lab <ics.forth>
*/

#include <idc.idc>

static main(){

auto ea,temp_ea,f_end,next_func,pEnd,x;
auto i =1,temp_i,arrN=0,szFilePath, hFile;
auto constr_arr = object();
auto prev_is_constr = 0, constr_arr_index = 0,Name_record = object(),name_rec_cnt = 0,prev_prev_is_constr = 0;
auto func_name;
auto vtt_ea,temp2_ea,next_addr,virtual_indicator=0;
auto prev_base = object(),base_cnt = 0;
auto prev_derived = object(),derived_cnt = 0;
auto multiple_inh = object(),multiple_inh_cnt=0,buf_multiple_inh_cnt=0,prev_is_multiple=0,this_no_multiple=0,this_last_multiple=0;
auto strict_check = 0;

SetStatus(IDA_STATUS_WORK);


/*linear address of first segment*/
ea = FirstSeg();

/* Request output header file*/
	SetStatus(IDA_STATUS_WAITING);
	if ((szFilePath = AskFile(1, "*.txt", "Select output dump file:")) == 0)
	{
		Message("Aborted.");
		SetStatus(IDA_STATUS_READY);
		return;
	}

//Message("\npAddress = ");
print(ea);

next_func = NextFunction(ea);
Message("%d\t",i);
i=i+1;

Message("Function Name: <"+atoa(ea)+">\n");

if ((hFile = fopen(szFilePath, "wb")) != 0){
auto szFuncName, szFullName,k;
/*FIND ALL FUNCTION INSIDE SEGMENT (INCLUDING CONSTRUCTORS)*/
next_func = NextFunction(ea);/*return next function's start address*/
while(next_func != -1){
	Message("%d\t",i);
	Message("Function Name: <"+atoa(ea)+">\n");
	i = i+1;
	temp_i = temp_i+1;
	temp_ea = ea;
	f_end = FindFuncEnd(ea);
	if(NextFunction(ea)==-1){break;}
	/*LOCATE FUNCTION CALLS INSIDE FUNCTIONS-CONSTRUCTORS*/
	for ( temp_ea ; temp_ea <= f_end; temp_ea = NextAddr(temp_ea) ) {
		x = Rfirst0(temp_ea); 	/*next code xref from temp_ea*/
		Name_record[name_rec_cnt] = Name(x);
		name_rec_cnt = name_rec_cnt + 1;

        if ( x != BADADDR) {
			Message("  Function call from <"+atoa(temp_ea)+">   to   <"+Name(x)+" : "+atoa(x)+">\n");
			/*IF CALL TO CONSTRUCTOR IN MAIN FOR GCC ANS MVC*/
			if(strstr(Name(x),"_Znw") != -1 || strstr(Name(x),"YAPAXI") != -1){	/*if previous call refers to new()*/
				prev_is_constr = 1;
				if(strstr(Name(x),"YAPAXI") != -1){/*mvc has one more cross reference after call to new <jump if zero>*/
					prev_prev_is_constr = 1;
				}
			}
			else if(prev_is_constr == 1){/*FOR CONSTRUCTORS IN MAIN OR EMBEDDED OBJECTS ON GCC*/
				if(prev_prev_is_constr == 0){
					Message("This is a call to a constructor -------------------------------------------------------------------------\n");
					constr_arr[arrN] = Name(x);
					arrN = arrN + 1;
					prev_is_constr = 0;
				}
				else{
					prev_is_constr = 0;
				}
			}
			else if(prev_is_constr == 0 && prev_prev_is_constr == 1){
				//fprintf(hFile,"This is a call to constructor in MVC!\n");
				Message("This is a call to a constructor FOR MVC -------------------------------------------------------------------------\n");
				constr_arr[arrN] = Name(x);
				arrN = arrN + 1;
				prev_prev_is_constr = 0;
			}
			else{/*FOR NOT EMBEDDED OBJECTS*/
				/*FIND IF FUNCTION CALL IS INSIDE A DECLARED CONSTRUCTOR HERE!*/
				for(constr_arr_index=0; constr_arr_index < arrN; constr_arr_index = constr_arr_index +1){
					func_name = GetFunctionName(temp_ea);
					if((strstr(atoa(temp_ea),constr_arr[constr_arr_index]) != -1)
					|| (func_name == constr_arr[constr_arr_index])){
						strict_check = 1;
						if(temp_i == i){
							temp2_ea = temp_ea;
							next_addr = NextAddr(temp2_ea+8);	/*  ZTT => Virtual*/
							if(strstr(GetDisasm(next_addr),"_ZTT") != -1){
								Message("----VIRTUAL INHERITANCE, constructor "+constr_arr[constr_arr_index]+"  calls: "+Name(x)+ "\n");
								virtual_indicator = 1;
								fprintf(hFile,"----VIRTUAL INHERITANCE 1, class "+substr(constr_arr[constr_arr_index],4,strlen(constr_arr[constr_arr_index])-4)+"  extends: "+substr(Name(x),4,strlen(Name(x))-4)+ "\n");
							}
							else{
								if(this_no_multiple == 0 && prev_is_multiple ==1){
									auto m=0;
									fprintf(hFile,prev_derived[derived_cnt-1]+" extends: ");
									for(m=0; m<buf_multiple_inh_cnt; m=m+1){
										fprintf(hFile,multiple_inh[m]+"\t");
									}
									fprintf(hFile,"\n");
								}
								this_no_multiple = 1;
								Message("----INHERITANCE, constructor "+constr_arr[constr_arr_index]+"  calls: "+Name(x)+ "\n");
								fprintf(hFile,substr(constr_arr[constr_arr_index],4,strlen(constr_arr[constr_arr_index])-4)+"  extends: "+substr(Name(x),4,strlen(Name(x))-4)+ "\n");
								prev_base[base_cnt] = substr(Name(x),4,strlen(Name(x))-4);
								base_cnt = base_cnt + 1;
								prev_derived[derived_cnt] = substr(constr_arr[constr_arr_index],4,strlen(constr_arr[constr_arr_index])-4);
								derived_cnt = derived_cnt + 1;
								multiple_inh[multiple_inh_cnt] = prev_base[base_cnt-1];
								multiple_inh_cnt = multiple_inh_cnt + 1;
							}
						}
						else{
							if(virtual_indicator == 0 && temp_i > i ){
								prev_is_multiple = 1;
								this_no_multiple = 0;
								Message("----MULTIPLE INHERITANCE, constructor "+constr_arr[constr_arr_index]+"  calls: "+Name(x)+ "\n");
								fprintf(hFile,"----MULTIPLE 2 INHERITANCE, class "+substr(constr_arr[constr_arr_index],4,strlen(constr_arr[constr_arr_index])-4)+"  extends: "+substr(Name(x),4,strlen(Name(x))-4)+ "\n");
								prev_base[base_cnt] = substr(Name(x),4,strlen(Name(x))-4);
								base_cnt = base_cnt + 1;
								prev_derived[derived_cnt] = substr(constr_arr[constr_arr_index],4,strlen(constr_arr[constr_arr_index])-4);
								derived_cnt = derived_cnt + 1;
								multiple_inh[multiple_inh_cnt] = prev_base[base_cnt-1];
								multiple_inh_cnt = multiple_inh_cnt + 1;
								buf_multiple_inh_cnt = multiple_inh_cnt;
							}
				/*NO*/			else if(virtual_indicator == 1 && temp_i > i ){
								Message("----VIRTUAL INHERITANCE, constructor "+constr_arr[constr_arr_index]+"  calls: "+Name(x)+ "\n");
								fprintf(hFile,"----VIRTUAL INHERITANCE 2, class "+substr(constr_arr[constr_arr_index],4,strlen(constr_arr[constr_arr_index])-4)+"  extends: "+substr(Name(x),4,strlen(Name(x))-4)+ "\n");
							}
				/*NO*/			else{
								Message("----INHERITANCE, constructor "+constr_arr[constr_arr_index]+"  calls: "+Name(x)+ "\n");
								fprintf(hFile,"----INHERITANCE 2, class "+substr(constr_arr[constr_arr_index],4,strlen(constr_arr[constr_arr_index])-4)+"  extends: "+substr(Name(x),4,strlen(Name(x))-4)+ "\n");
							}
						}


						Message("constructor "+constr_arr[constr_arr_index]+"  calls: "+Name(x)+ "\n");

						/*IF CALLEE HAS _ZN => IS CONSTRUCTOR => EXTEND CONSTR_ARR*/
						/*polu strict*/
						if(strstr(Name(x),"_ZN") != -1){
							constr_arr[arrN] = Name(x);
							arrN = arrN + 1;
						}
					}
				}
			}
/*NO STRICT CHECK FOR INHERITANCE! remove for stricter. true negatives*/
			//if(strict_check == 0 && strstr(Name(x),"_ZN") != -1 && strstr(atoa(temp_ea),"_ZN") != -1){
			//	fprintf(hFile,substr(atoa(temp_ea),10,strlen(atoa(temp_ea))-13)+"  extends: "+substr(Name(x),4,strlen(Name(x))-4)+ "\n");
			//}
			strict_check = 0;
			temp_i = temp_i +1;
			x = Rnext0(temp_ea,x);
        }
        while ( x != BADADDR) {
			Message("  Function call from <"+atoa(temp_ea)+">   to   <"+Name(x) +" : "+atoa(x)+">\n");
			/*IF CALL TO CONSTRUCTOR IN MAIN*/
			if(strstr(Name(x),"_Znw") != -1){//if previous call refers to new()
				prev_is_constr = 1;
			}
			else if(prev_is_constr == 1){
				Message("This is a call to a constructor in main!\n");
				constr_arr[arrN] = Name(x);
				arrN = arrN + 1;
				prev_is_constr = 0;
			}
			x = Rnext0(temp_ea,x);
        }
    }
	multiple_inh_cnt = 0;
	virtual_indicator = 0;
	ea=next_func;
	next_func = NextFunction(ea);
	temp_i=i;
}
/*If it is a last multiple inheritance, i print the hole multiple_inh[] in a loop*/
if(this_no_multiple == 0 && prev_is_multiple ==1){
	auto f=0;
	fprintf(hFile,prev_derived[derived_cnt-1]+" extends: ");
	for(f=0; f<buf_multiple_inh_cnt; f=f+1){
		fprintf(hFile,multiple_inh[f]+"\t");
	}
	fprintf(hFile,"\n");
}

Message("\nNo more functions in Segment!");

}
/*Uncomment to check constructor array*/
/*
fprintf(hFile,constr_arr[0]+"\n");
fprintf(hFile,constr_arr[1]+"\n");
fprintf(hFile,constr_arr[2]+"\n");
fprintf(hFile,constr_arr[3]+"\n");
fprintf(hFile,constr_arr[4]+"\n");
fprintf(hFile,constr_arr[5]+"\n");
fprintf(hFile,constr_arr[6]+"\n");
fprintf(hFile,constr_arr[7]+"\n");
*/
}//main
