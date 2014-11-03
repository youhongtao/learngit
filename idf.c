#include "idf_struct.h"
#include "idf_acsmx.h"
#include "idf_debug.h"
#include "idf_des.h"
#include "idf_xml.h"
// this version is test rule idf rate
INT8     IDF_VERSION[] = "libidf.so version:3.0.61 .\n";    //版本信息
UINT32	 IDF_VERSION_NUM = 30061;						 //计算方法:3*10000 + 0 * 100 + 10

UINT8        debug_switch = 0;                            //调试开关
UINT8        debug_print_level = 0;                       //暂未使用， 日志打印级别

//----------------------全局变量定义---------------------------
IDF_TREE             *g_idf_tree;    //规则树

IDF_PORT_IP_MAP_TBL  *g_port_ip_tbl;   //端口和 IP 表
IDF_PORT_IP_MAP_TBL  *g_ftp_port_ip_tbl; //ftp 端口和ip 表
IDF_HEADER           *g_string_idf_header;      //string规则头链表       
IDF_IP_HASH_TBL      *g_ip_hash_tbl;  //ip规则hash表
IDF_AC_STRING        *g_ac_string;     //ac_string链表
IDF_PORT_PROTO_TBL   g_port_proto_tbl; //端口协议映射表
IDF_BIT_MAP          g_tcp_bit_map;    //tcp位图映射
IDF_BIT_MAP          g_udp_bit_map;    //udp位图映射
UINT8 g_bitmap_cmp[IDF_MAX_BITMAP_LEN] = {0}; //全0， 用来比较位图中的数据是否全部为0
IDF_STRING_SPECIAL   g_string_get; //保存包含 "GET "规则的信息
IDF_STRING_SPECIAL   g_string_ooo;  //保存包含0x00 00 00规则的信息
IDF_STRING_SPECIAL   g_string_oo; //保存包含0x00 00规则的信息

ACSM_STRUCT         *g_acsm;               //AC匹配使用的链表
INT32                g_pattern_num = 0;    //计数值
INT32                g_init_count_num = 0; //初始化的次数
INT32                g_pid_num = 0;        //计数值

FILE    *g_fp;                 //日志文件句柄
T_CS    g_print_lock;          //日志打印锁
INT8    g_cfg_file_name[] = "appidf.cfg";     //配置的名称


INT8   g_special_string_get[] = "GET ";   //"GET "特殊字符串
INT8   g_special_string_ooo[3] = {0};     //"0x00 00 00"特殊字符串
INT8   g_special_string_oo[2] = {0};      //"0x00 00"特殊字符串

UINT8 xml_rule_key[8] = {0};   // xml 规则密码 
UINT32 idf_read_xml_num = 0;  //允许读取的读取的xml规则
#define XML_RULE_NUMBER 800	  // xml 规则数
time_t  idf_valid_start_time = 0;	// 软件的有效开始时间
time_t  idf_valid_end_time = 0;		// 软件的有效结束时间
INT8 *license_release_date = NULL;
INT8 *license_release_version = NULL;

UINT8  g_license_flag   =  RESET_FLAG;//是否读取license_ss， SET_FLAG表示未读取

UINT8    IDF_STATE_POSSIBLE         = 0x01;
UINT8    IDF_STATE_STATUS_POSSIBLE  = 0x02;
UINT8    IDF_STATE_CURRENT_STATUS   = 0x04;
UINT8    IDF_STATE_USE_STATUS       = 0x08;
UINT8 	 IDF_IS_PORT				= 0x10;
#define TIME_LENGTH  64



INT32 check_idf_bit_position(IDF_HEADER *idf_header, IDF_INFO *idf_info, UINT8 *flag);
inline INT32 check_idf_header(IDF_HEADER *header, IDF_INFO *idf_info, UINT8 *flag);
INT32 free_ac_string(IDF_AC_STRING *input_list);
INT32 free_idf_header_list(IDF_HEADER * list_header);
INT32 free_idf_map(IDF_TREE  *idf_tree);
INT32 free_idf_resource(void);
INT32 free_idf_tree(IDF_TREE_NODE*tree_root, INT32 node_num);
INT32 free_ip_hash_tbl(IDF_IP_HASH_TBL *input_tbl);
INT32 free_port_ip_tbl(IDF_PORT_IP_MAP_TBL *input_tbl);
void  get_cfg(void);
INT32 get_idf_header(IDF_TREE_NODE *tree_root, IDF_HEADER **output_header, INT32 len);
INT32 get_idf_proto_id(IDF_INFO *idf_info);
INT32 get_ip_hash_proto_id(IDF_INFO *idf_info, IDF_IP_HASH_TBL *ip_hash_tbl, UINT8 *flag,UINT8 is_des);
INT32 get_PASV_ftp_port(const char *payload, UINT16 payload_len, UINT16 *output_port);
INT32 get_port_ip_proto_id(IDF_INFO * idf_info,UINT8 type, UINT8 *flag, UINT8 is_ftp);
INT32 get_port_proto_id(IDF_INFO *idf_info, UINT8 *flag);
INT32 init_identifier_map(IDF_TREE *idf_tree, INT8 *list);
INT32 init_ip_hash_tbl(IDF_IP_HASH_TBL **hash_table, INT32 buck_num, INT32 node_num);
INT32 init_pkt_proto(IDF_INFO *idf_info);
INT32 init_port_ip_tbl(IDF_PORT_IP_MAP_TBL **port_ip_tbl);
INT32 init_special_string(void);
INT32 init_tree(IDF_TREE_NODE **tree_root, INT32 node_len[], INT32 node_num);
INT32 insert_ac_string(void *idf_rule, UINT32 proto_id, UINT8 is_tcp, UINT32 bit_position);
INT32 insert_ac_sub_list(IDF_AC_STRING *ac_string, UINT32 proto_id, UINT8 is_tcp, UINT32 bit_position, IDF_TYPE type, INT16 offset);
INT32 insert_bitmap_map_tbl(void *idf_rule, UINT8 is_tcp, UINT32 *bit_position);
INT32 insert_ip_hash_node(IDF_IP_NODE insert_node, IDF_IP_HASH_TBL *ip_hash_tbl, UINT16 port_start, UINT16 port_end);
void *port_ip_tbl_scan(void *_arg);
INT32 proc_ac(void);
INT32 proc_ac_match(IDF_INFO *idf_info, UINT8 *flag);
INT32 proc_first_packet(IDF_INFO *idf_info, UINT8 *flag);
INT32 proc_idf(IDF_INFO *idf_info,IDF_TREE_NODE *tree_root);
INT32 proc_idf_header(IDF_HEADER *idf_header, IDF_INFO *idf_info, UINT8 *flag);
INT32 proc_idf_rule(void *list_header,  IDF_INFO *idf_info, UINT32 proto_id, UINT8 *output_flag);
INT32 proc_idf_tree(IDF_INFO *idf_info, IDF_TREE_NODE *tree_root);
INT32 proc_special_string(INT32 bit_position, IDF_INFO *idf_info, UINT8 *flag);
INT32 proc_state(IDF_HEADER *header, IDF_INFO *idf_info,  UINT8 *flag);
INT32 proc_string(INT32 bit_position, IDF_INFO *idf_info, UINT8 *flag);
INT32 check_payload_first_byte(char *packet_payload, int packet_length);
inline INT32 proc_ftp_data(IDF_INFO *idf_info);

INT32 decrypt_license_ss();
INT32 verify_password_information();
INT32 decrypt(INT8 *temp_path, INT8 **content, INT32 *content_len);
INT8* get_license_information(INT8 *des, INT8 *str_start, INT8 *str_end);
INT32 get_information(INT8 *output);
INT8 *allocate_des_memory(INT8 *filename, INT32 *len);
void clear_port_ip_tbl();
void print_idf_rule(const INT8 *format, ...);
INT8 *idf_get_version_str(void);
UINT32 idf_get_version(void);
inline void proc_state_comm(IDF_HEADER *header, IDF_INFO *idf_info, UINT8 *flag);
inline void proc_state_status_comm(IDF_HEADER *header, IDF_INFO *idf_info, UINT8 *flag);
inline void proc_state_status_final(IDF_HEADER *header, IDF_INFO *idf_info, UINT8 *flag);

/*====================================================
函数名: init_ip_hash_tbl
功能:   初始化ip规则的hash表
入参:   **hash_table: hash表指针
              buck_num: hash表的桶数
              node_num: hash表中的节点数
出参:
返回值:  R_OK, R_ERROR
作者:  dingdong
时间:2013-11
说明:
======================================================*/
INT32 init_ip_hash_tbl(IDF_IP_HASH_TBL **hash_table, INT32 buck_num, INT32 node_num)
{
	INT32 i = 0;
	if(buck_num <= 0 || node_num <= 0)//参数检查
	{
		log_message(LOG_ERROR,  "%s:Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	if(NULL == ((*hash_table) = (IDF_IP_HASH_TBL *)i_calloc(sizeof(IDF_IP_HASH_TBL), 1, I_IDF, 0)))//申请hash表
	{
		log_message(LOG_ERROR, "%s: No memory.\n", __func__);
		return R_ERROR;
	}
	if(NULL == ((*hash_table)->tbl = i_calloc(sizeof(void *), buck_num, I_IDF, 0)))//申请hash桶
	{
		log_message(LOG_ERROR, "%s: No memory.\n", __func__);
		i_free(*hash_table);
		return R_ERROR;
	}
	if(NULL == ((*hash_table)->free_node = i_calloc(sizeof(IDF_IP_NODE), node_num, I_IDF, 0)))//申请hash节点
	{
		log_message(LOG_ERROR,  "%s: No memory.\n", __func__);
		i_free(*((*hash_table)->tbl));
		i_free((*hash_table));
		return R_ERROR;
	}
	(*hash_table)->store_address = (*hash_table)->free_node;//free空间时使用
	(*hash_table)->free_node_num = node_num; //空闲节点赋值
	(*hash_table)->buck_num = buck_num;   //保存桶数
	for(i = 0; i < node_num - 1; i++)   //循环将空闲节点串成链表， 最后一个节点的next指针已为空
	{
		(*hash_table)->free_node[i].next = &((*hash_table)->free_node[i + 1]);
	}
	return R_OK;
}
/*====================================================
函数名: insert_ip_hash_node
功能:   在ip hash表中插入节点
入参:  insert_node: 待插入的节点
             *ip_hash_tbl: ip hash表指针
出参:
返回值:  R_OK, R_ERROR
作者: dingdong
时间:2013-11
说明:
======================================================*/
INT32 insert_ip_hash_node(IDF_IP_NODE insert_node, IDF_IP_HASH_TBL *ip_hash_tbl, UINT16 port_start, UINT16 port_end)
{
	IDF_IP_NODE *temp = NULL;
	IDF_IP_NODE *ip_node = NULL;
	IDF_IP_NODE *pre_node = NULL;
	INT32 hash_value = -1;
	if(NULL == ip_hash_tbl)// 参数检查
	{
		log_message(LOG_ERROR,  "%s: Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	if(0 == ip_hash_tbl->free_node_num)//节点用完
	{
		log_message(LOG_ERROR,  "%s: There is no free node in ip_hash table.\n", __func__);
		return R_OK;
	}
	hash_value = insert_node.ip % ip_hash_tbl->buck_num;  //计算hash值
	ip_node = ip_hash_tbl->tbl[hash_value];
	while(1)
	{
		if(NULL != ip_node)
		{
			if(ip_node->ip == insert_node.ip && ip_node->is_tcp == insert_node.is_tcp)//ip已经存在，不正常，打印日志 
			{
				//log_message(LOG_ERROR,  "%s: The node has been existed,ip:%u, is_tcp:%d.\n", __func__, ip_node->ip, ip_node->is_tcp);
				
				return R_OK;
			}
			else//指向下一节点
			{
				pre_node = ip_node;
				ip_node = ip_node->next;
			}
		}
		else// ip_node为空
		{
			temp = ip_hash_tbl->free_node; //从空闲节点中取节点
			ip_hash_tbl->free_node = ip_hash_tbl->free_node->next;  
			(ip_hash_tbl->free_node_num)--;  //计数值减1
			memcpy(temp, &insert_node, sizeof(IDF_IP_NODE));  //复制节点值
			temp->next = NULL;                                //指针置空
			if(NULL == pre_node)   //前节点为空
				ip_hash_tbl->tbl[hash_value] = temp;  //直接在桶下添加  
			else
				pre_node->next = temp;                //添加节点

			temp->port_start = port_start;
			temp->port_end = port_end;
			return R_OK;
		}
	}
	
}
/*====================================================
函数名: insert_bitmap_map_tbl
功能:   在位图映射表中添加记录
入参:   *idf_rule:  规则指针
               is_tcp:  规则是否为tcp类型, SET_FLAG为是， RESET_FLAG 为否
出参:  *bit_position:  规则添加在映射表中的位置， 即在位图中
              的位置
返回值:  R_OK, R_ERROR
作者: dingdong
时间:2013-11
说明:
======================================================*/
INT32 insert_bitmap_map_tbl(void *idf_rule, UINT8 is_tcp, UINT32 *bit_position)
{
	IDF_BIT_MAP *temp_map = NULL;
	if(NULL == idf_rule || NULL == bit_position)//参数检查
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	if(SET_FLAG == is_tcp)//  选择映射表
		temp_map = &g_tcp_bit_map;
	else
		temp_map = &g_udp_bit_map;
	if(temp_map->used_num < IDF_MAP_SPECAIL_BITMAP)   //判断映射表中的记录值是否大于保留值
	{
		log_message(LOG_ERROR, "%s: The bitmap table do not init, used_num: %d.\n", __func__, temp_map->used_num);
		return R_ERROR;
	}
	if (temp_map->used_num >= IDF_BITMAP_NUM)
	{	
		log_message(LOG_ERROR, "%s:the bitamp table used out",__func__);
		return R_ERROR;
	}
	temp_map->bit_map[temp_map->used_num] = idf_rule; //保存指针
	*bit_position = temp_map->used_num;  //保存位置值
	(temp_map->used_num)++; //位置值加1
	return R_OK;
}
/*====================================================
函数名: insert_ac_sub_list
功能:   在ac_sub_list 链表中插入节点
入参:   *ac_string: ac_sub_list的外围结构体
               proto_id: 协议号
               is_tcp: 规则是否为tcp类型, SET_FLAG为是， RESET_FLAG 为否
               bit_position: 在位图中的位置
               type: 类型为URL 或者STRING
               offset: STRING规则中的偏移量
出参:  
返回值:  R_OK, R_ERROR
作者:dingdong
时间:2013-11
说明:
======================================================*/
INT32 insert_ac_sub_list(IDF_AC_STRING *ac_string, UINT32 proto_id, UINT8 is_tcp, UINT32 bit_position, IDF_TYPE type, INT16 offset)
{
	IDF_AC_SUB *ac_sub = NULL;
	if(NULL == ac_string)// 参数检查
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	if(NULL == (ac_sub = (IDF_AC_SUB *)i_calloc(sizeof(IDF_AC_SUB), 1, I_IDF, 0)))//申请节点空间
	{
		log_message(LOG_ERROR, "%s: No memory.\n", __func__);
		return R_ERROR;
	}
	ac_sub->proto_id = proto_id;
	ac_sub->bit_position = bit_position;
	ac_sub->is_tcp = is_tcp;
	ac_sub->offset = offset;
	ac_sub->type = type;
	ac_sub->next = ac_string->string_header;
	ac_string->string_header = ac_sub;
	return R_OK;
}
/*====================================================
函数名: insert_ac_string
功能:   在ac_string链表中插入节点
入参:   *string:  字符串
               string_len: 字符串的长度
               proto_id: 协议号
               is_tcp: 是否为tcp类型, SET_FLAG为是， RESET_FLAG 为否
               bit_position:  在位图中的位置
出参:  
返回值:  R_OK, R_ERROR
作者:dingdong
时间:2013-11
说明:
======================================================*/
INT32 insert_ac_string(void *idf_rule, UINT32 proto_id, UINT8 is_tcp, UINT32 bit_position)
{
	IDF_AC_STRING  *temp_ac = NULL;
	IDF_AC_STRING *pre_temp_ac = NULL;
	T_IDF_RULE    *rule = NULL;
	INT8 *string = NULL;
	UINT32 string_len = 0;
	IDF_URL *idf_url = NULL;
	IDF_STRING *idf_string = NULL;
	IDF_HTTP_REF *idf_http_ref = NULL;
	IDF_HTTP_HDR *idf_http_hdr = NULL;
	IDF_HTTP_AGENT *idf_http_agent = NULL;
	IDF_HTTP *idf_http = NULL;
	IDF_TYPE  temp_type;
	INT16 offset = 0;
	if(NULL == idf_rule || bit_position < 0 || bit_position >= IDF_BITMAP_NUM) //参数检查
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	rule = (T_IDF_RULE *)idf_rule;
	if(URL != rule->type && STRING != rule->type 
		&& HTTP_REF != rule->type && HTTP_HDR != rule->type
		&& HTTP_AGENT != rule->type
		&& HTTP != rule->type)
	{
		log_message(LOG_ERROR, "%s: The type of rule is wrong.\n", __func__);
		return R_ERROR;
	}
	
	if(URL == rule->type)
	{
		temp_type = URL;
		idf_url = (IDF_URL *)idf_rule;
		string = idf_url->content;
		string_len = idf_url->content_len;
	}
	else if(STRING == rule->type)
	{
		temp_type = STRING;
		idf_string = (IDF_STRING *)idf_rule;
		string = idf_string->content;
		string_len = idf_string->content_len;
		offset = idf_string->offset;
	}
	else if(HTTP_REF == rule->type)
	{
		temp_type = HTTP_REF;
		idf_http_ref = (IDF_HTTP_REF *)idf_rule;
		string = idf_http_ref->content;
		string_len = idf_http_ref->content_len;
	}
	else if(HTTP_HDR == rule->type)
	{
		temp_type = HTTP_HDR;
		idf_http_hdr = (IDF_HTTP_HDR *)idf_rule;
		string = idf_http_hdr->content;
		string_len = idf_http_hdr->content_len;

	}
	else if (HTTP_AGENT == rule->type)
	{
		temp_type = HTTP_AGENT;
		idf_http_agent = (IDF_HTTP_AGENT*)idf_rule;
		string = idf_http_agent->content;
		string_len = idf_http_agent->content_len;
	}
	else
	{
		temp_type = HTTP;
		idf_http = (IDF_HTTP*)idf_rule;
		string = idf_http->content;
		string_len = idf_http->content_len;
	}
	
	if(NULL == string ||  string_len <= 0 || string_len > IDF_MAX_STRING_LEN - 1)
	{
		log_message(LOG_ERROR, "%s: The string is invalid.\n", __func__);
		return R_ERROR;
	}
	temp_ac = g_ac_string;
	while(NULL != temp_ac)
	{
		if(temp_ac->content_length != string_len)//字符长度不匹配， 继续循环
		{
			pre_temp_ac = temp_ac;
			temp_ac = temp_ac->next;
			continue;
		}
		else if(0 == memcmp(temp_ac->content, string, temp_ac->content_length))//内容比对
		{
			if(R_OK != insert_ac_sub_list(temp_ac, proto_id, is_tcp, bit_position, temp_type, offset))//内容相同时插入节点
			{
				log_message(LOG_ERROR, "%s: insert_ac_sub_list return R_ERROR.\n", __func__);
				return R_ERROR;
			}
			break;
		}
		else//内容不匹配， 继续循环
		{
			pre_temp_ac = temp_ac;
			temp_ac = temp_ac->next;
		}
	}
	if(NULL == temp_ac)//没有在链表中找到相应的字符串
	{
		if(NULL == (temp_ac = (IDF_AC_STRING *)i_calloc(sizeof(IDF_AC_STRING), 1, I_IDF, 0)))//申请IDF_AC_STRING结构空间
		{
			log_message(LOG_ERROR, "%s: No memory.\n", __func__);
			return R_ERROR;
		}
		memcpy(temp_ac->content, string, string_len); //string赋值
		temp_ac->content_length = string_len;//长度赋值
		temp_ac->pid = ++g_pid_num;
		if(R_OK != insert_ac_sub_list(temp_ac, proto_id, is_tcp, bit_position, temp_type, offset))//插入ac_sub_list链表
		{
			log_message(LOG_ERROR, "%s: insert_ac_sub_list return R_ERROR.\n", __func__);
			return R_ERROR;
		}
		if(NULL == pre_temp_ac)  //插入ac_string链表
			g_ac_string = temp_ac;
		else
			pre_temp_ac->next = temp_ac;
	}
	return R_OK;
}

/*====================================================
函数名: init_string_header_list
功能:   根据g_string_idf_header 链表初始化映射表和ac字符串
入参:  
出参:  
返回值:  R_OK, R_ERROR
作者:dingdong
时间:2013-12
说明:
======================================================*/
INT32 init_string_header_list(void)
{
	IDF_STRING  *idf_string = NULL;
	IDF_URL     *idf_url = NULL;
	IDF_HEADER *idf_header = NULL;
	T_IDF_RULE *idf_rule = NULL;
	void *rule = NULL;
	UINT32 bit_position = 0;
	IDF_BIT_MAP *temp_map = NULL;
	
	if(NULL == g_string_idf_header)
		return R_OK;
	idf_header = g_string_idf_header;
	while(NULL != idf_header)
	{
		if(NULL == idf_header->idf_rule)
		{
			log_message(LOG_ERROR, "%s: There are no rules in idf_header.\n",  __func__);
			return R_ERROR;
		}
		idf_rule = (T_IDF_RULE *)(idf_header->idf_rule);
		while(NULL != idf_rule)
		{
			if(URL == idf_rule->type || HTTP_REF == idf_rule->type 
				|| HTTP_HDR == idf_rule->type || HTTP_AGENT == idf_rule->type
				|| HTTP == idf_rule->type)
			{
				rule = (void *)idf_rule;
			}
			else if(STRING == idf_rule->type)
			{
				idf_string = (IDF_STRING *)idf_rule;
				if((1 == idf_string->content_len)
					|| (SET_FLAG == idf_string->not_flag)
					|| (2 == idf_string->content_len && 0 == memcmp(idf_string->content, g_special_string_oo, idf_string->content_len))
					|| (3 == idf_string->content_len && 0 == memcmp(idf_string->content, g_special_string_ooo, idf_string->content_len))
					|| (strlen(g_special_string_get) == idf_string->content_len && 0 == memcmp(idf_string->content, g_special_string_get, idf_string->content_len)))
				{//长度为1的字符串或特殊字符串， 不进行处理
					idf_rule = idf_rule->next;
					continue;
				}
				else
				{
					rule = (void *)idf_rule;
				}
			}
			else//非string和url, http_ref规则
			{
				idf_rule = idf_rule->next;
				continue;
			}
			if(R_OK != insert_bitmap_map_tbl((void *)rule,idf_header->is_tcp, &bit_position))//在映射表中添加记录
			{
				if(SET_FLAG == idf_header->is_tcp)//  选择映射表
					temp_map = &g_tcp_bit_map;
				else
					temp_map = &g_udp_bit_map;
				if (temp_map->used_num >= IDF_BITMAP_NUM)
				{

					idf_rule = idf_rule->next;
					continue;
				}
				log_message(LOG_ERROR,	"%s: insert_bitmap_map_tbl return R_ERROR.\n", __func__);
				return R_ERROR;
			}
			if(R_OK != insert_ac_string((void *)rule, idf_header->proto_id, idf_header->is_tcp, bit_position))//在AC_string中添加记录
			{
				log_message(LOG_ERROR,	"%s: insert_ac_string return R_ERROR.\n", __func__);
				return R_ERROR;
			}
			add_new_bit_record(idf_header, bit_position);//在idf_header中的 bit_position数组中添加记录
			idf_rule = idf_rule->next;
		}
		idf_header = idf_header->next;
	}
	return R_OK;
}
/*====================================================
函数名: get_ip_hash_proto_id
功能:   从ip hash表中获取协议号
入参:   *idf_info: 流信息结构体
              *ip_hash_tbl: ip hash表
出参:   *flag: R_NO表示找到协议号，不需要继续往下走
               R_YES表示需要往下走
返回值:  R_OK, R_ERROR
作者:dingdong
时间:2013-11
说明:
======================================================*/
INT32 get_ip_hash_proto_id(IDF_INFO *idf_info, IDF_IP_HASH_TBL *ip_hash_tbl, UINT8 *flag, UINT8 is_des)
{
	INT32 hash_value = -1;
	IDF_IP_NODE *ip_node = NULL;
	UINT8 is_tcp = 0;
	if(NULL == idf_info || NULL == ip_hash_tbl ||(is_des != SET_FLAG && is_des != RESET_FLAG))//参数检查
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	*flag = R_NO; //设置默认值
    if (SET_FLAG == is_des)
    { 
        if(IDF_IPV4 != idf_info->dip.ip_type) //暂只支持ipv4
    	{
	    	*flag = R_YES;
	    	return R_OK;
	    }
	    is_tcp = (IPPROTO_TCP == idf_info->l4_type) ? SET_FLAG : RESET_FLAG;//根据是否为tcp设置is_tcp
	    hash_value = idf_info->dip.ip4_addr.s_addr % ip_hash_tbl->buck_num;//计算hash值
	    ip_node = ip_hash_tbl->tbl[hash_value];
    }
    else 
    {
        if(IDF_IPV4 != idf_info->sip.ip_type) //暂只支持ipv4
    	{
	    	*flag = R_YES;
	    	return R_OK;
	    }
	    is_tcp = (IPPROTO_TCP == idf_info->l4_type) ? SET_FLAG : RESET_FLAG;//根据是否为tcp设置is_tcp
	    hash_value = idf_info->sip.ip4_addr.s_addr % ip_hash_tbl->buck_num;//计算hash值
	    ip_node = ip_hash_tbl->tbl[hash_value];
    }
    while(NULL != ip_node)
	{
		if(ip_node->is_tcp == is_tcp)  //tcp，udp匹配
		{
			if(ip_node->ip == idf_info->sip.ip4_addr.s_addr)//sip匹配
			{
				if(0 == ip_node->port_start && 0 == ip_node->port_end)//判断是否使用端口
				{
					idf_info->proto_id = ip_node->proto_id;
#ifdef RULE_RATE_TEST
					bit_set_value(&idf_info->rule_use, IPV4_RATE);
#endif
					return R_OK;
				}
				else
				{
					if(idf_info->sport >= ip_node->port_start && idf_info->sport <= ip_node->port_end)//端口匹配
					{
						idf_info->proto_id = ip_node->proto_id;
#ifdef RULE_RATE_TEST
						bit_set_value(&idf_info->rule_use, IPV4_RATE);
						bit_set_value(&idf_info->rule_use, TYPE_PORT_RATE);
#endif

						return R_OK;
					}
				}
			}
			else if(ip_node->ip == idf_info->dip.ip4_addr.s_addr) //dip匹配
			{
				if(0 == ip_node->port_start && 0 == ip_node->port_end)//判断是否使用端口
				{
					idf_info->proto_id = ip_node->proto_id;
#ifdef RULE_RATE_TEST
					bit_set_value(&idf_info->rule_use, IPV4_RATE);
#endif

					return R_OK;
				}
				else
				{
					if(idf_info->dport >= ip_node->port_start && idf_info->dport <= ip_node->port_end)//端口匹配
					{
						idf_info->proto_id = ip_node->proto_id;
#ifdef RULE_RATE_TEST
						bit_set_value(&idf_info->rule_use, IPV4_RATE);
						bit_set_value(&idf_info->rule_use, TYPE_PORT_RATE);
#endif

						return R_OK;
					}
				}
			}	
		}
		ip_node = ip_node->next; //指向下一节点
	}
	*flag = R_YES;
	return R_OK;
}
/*====================================================
函数名: get_PASV_ftp_port
功能:   在FTP报文中获取端口
入参:    *payload: 负载数据
                payload_len: 负载长度
出参:   *output_port: 获取的端口号， 如获取失败，填写默认
               端口20
返回值:  R_OK, R_ERROR
作者: dingdong
时间:2013-10-24
说明:
  数据的原始报文格式为:
  227 Entering Passive Mode (222,240,210,154,229,193).
  获取的端口号使用括号内的后面两位， 即229和193
  由这两个数字获取的端口号的计算方法为229 * 256 + 193
    = 58817,  即229为两字节端口的高字节， 193为低字节

   229 Entering Extended Passive Mode (|||51374|)

   sscanf不可重入， 需修改
======================================================*/
INT32 get_PASV_ftp_port(const char *payload, UINT16 payload_len, UINT16 *output_port)
{
	INT8 cmp_str[] = "227";
	INT8 temp_str[] = "229";
	INT32 data[6] = {0};
	INT8 load[PASV_FTP_MAX_LEN] = {0};
	if(NULL == payload || NULL == output_port || payload_len < 0)//参数检查
	{
		log_message(LOG_ERROR, "%s:Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	*output_port = 20;//默认端口
	if(payload_len < PASV_FTP_MIN_LEN || payload_len >= PASV_FTP_MAX_LEN)//长度检查
		return R_OK;
	if(0 == memcmp(payload, cmp_str, strlen(cmp_str)))//是否以227为负载的开始
	{
		memcpy(load, payload, payload_len);//保证字符串的最后一位为'\0'
		sscanf(load, "%*[^(](%d,%d,%d,%d,%d,%d)%*[^)]", &data[0], &data[1], &data[2], &data[3], &data[4], &data[5]);//获取
		if((0 == data[4] && 0 == data[5]) || data[4] >= 256 || data[5] >= 256)// 有效性检查
			return R_OK;
		*output_port = (data[4] << 8) + data[5];//计算结果
		return R_OK;
	}
	if(0 == memcmp(payload, temp_str, strlen(temp_str)))//处理以229为负载的开始
	{
		memcpy(load, payload, payload_len);//保证字符串的最后一位为'\0'
		sscanf(load, "%*[^(](|||%d|)%*[^)]", &data[0]);
		if(0 == data[0])
			return R_OK;
		*output_port = data[0];
	}
	return R_OK;
}
/*====================================================
函数名: check_idf_bit_position
功能:   检查规则头下的使用了ac的规则是否都匹配
入参:   *idf_header: 规则头节点
               *idf_info: 检查内容
出参:  *flag :            不需要处理 R_NO
                                   需要处理      R_YES
返回值:  R_OK, R_ERROR
作者:dingdong
时间:2013-11
说明: 
======================================================*/
INT32 check_idf_bit_position(IDF_HEADER *idf_header, IDF_INFO *idf_info, UINT8 *flag)
{
	INT32 i = 0;
	if(NULL == idf_header || NULL == idf_info || NULL == flag)
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	*flag = R_YES;
	for(i = 0; i < idf_header->bit_used_num; i++)//检查规则头中记录的每一个使用了AC的规则是否已匹配
	{
		if(idf_header->bit_position[i] < IDF_MAP_SPECAIL_BITMAP)//为特殊字符时，继续循环
			continue;
		else
		{
			if(R_YES != bit_check_position(idf_info->bitmap, IDF_BITMAP_NUM, idf_header->bit_position[i]))
			{
				*flag = R_NO;//不走规则
				continue;//即使不需要走规则了， 还需要将后面的bit_position处理掉
			}
		}
				
	}
	return R_OK;
}
/*====================================================
函数名: proc_ac_match
功能:   处理AC匹配后的位图
入参:   *idf_info: 检查内容
出参:   *flag :            不需要继续处理 R_NO
                                   需要继续处理      R_YES
返回值:  R_OK, R_ERROR
作者:dingdong
时间:2013-11
说明: 
======================================================*/
INT32 proc_ac_match(IDF_INFO *idf_info, UINT8 *flag)
{
	UINT32 bit_position = 0;
	if(NULL == idf_info || NULL == flag )
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	if(R_YES == bit_is_all_zero(idf_info->bitmap, g_bitmap_cmp, IDF_MAX_BITMAP_LEN))//检查位图是否为全0
	{
		*flag = R_YES; //需要继续走规则树
		return R_OK;
	}
	while(1)
	{
		if(R_OK == bit_get_one_position(idf_info->bitmap, IDF_MAX_BITMAP_LEN, &bit_position))// 从位图中获取一位
		{
			if(bit_position < IDF_MAP_SPECAIL_BITMAP)//获取的位在保留区内， 为特殊字符串处理
			{	
				if (IDF_STRING_GET_POSITION != bit_position)
				{
					proc_special_string(bit_position, idf_info, flag);
				}
				bit_reset_position(idf_info->bitmap, IDF_MAX_BITMAP_LEN, bit_position);
			}
			else
				proc_string(bit_position, idf_info, flag); //普通字符串处理
		}
		else//位图全部为0了
			break;
		if(R_NO == *flag)//已识别
			break;
	}
	return R_OK;
}
/*====================================================
函数名: proc_special_string
功能:   处理特殊字符串
入参:  bit_position:  位图中的位置值
             *idf_info:  检查内容
出参:   *flag :            不需要继续处理 R_NO
                                   需要继续处理      R_YES
返回值:  R_OK, R_ERROR
作者:dingdong
时间:2013-11
说明: 
======================================================*/
INT32 proc_special_string(INT32 bit_position, IDF_INFO *idf_info, UINT8 *flag)
{
	INT32 i = 0;
	IDF_STRING_SPECIAL *temp_string_special = NULL;
	IDF_HEADER *idf_header = NULL;
	IDF_STRING  *idf_string = NULL;
	if(bit_position >= IDF_MAP_SPECAIL_BITMAP || NULL == idf_info || NULL == flag )
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	if(IPPROTO_TCP  == idf_info->l4_type)//获取bit_position对应的指针
		temp_string_special = (IDF_STRING_SPECIAL *)g_tcp_bit_map.bit_map[bit_position];
	else
		temp_string_special = (IDF_STRING_SPECIAL *)g_udp_bit_map.bit_map[bit_position];
	if(NULL == temp_string_special)
	{
		log_message(LOG_ERROR, "%s: ERROR. gdb me.\n", __func__);
		return R_ERROR;
	}
	for(i = 0 ; i < temp_string_special->used_num; i++)//访问对应的规则头
	{
		idf_string = (IDF_STRING *)(temp_string_special->string_special[i]);
		idf_header = idf_string->idf_header;
		if(idf_header->is_tcp != (idf_info->l4_type == IPPROTO_TCP ? SET_FLAG : RESET_FLAG))
		{
			continue;
		}
		proc_idf_header(idf_header, idf_info, flag);
		if(R_NO == *flag)//未识别， 或识别的为可能协议
			break;
	}
	return R_OK;
}
/*====================================================
函数名: proc_string
功能:   处理字符串规则(包括url)
入参:  bit_position:  位图中的位置值
             *idf_info:  检查内容
出参:   *flag :            不需要继续处理 R_NO
                                   需要继续处理      R_YES
返回值:  R_OK, R_ERROR
作者:dingdong
时间:2013-11
说明: 
======================================================*/
INT32 proc_string(INT32 bit_position, IDF_INFO *idf_info, UINT8 *flag)
{
	T_IDF_RULE *idf_rule = NULL;
	IDF_STRING *idf_string = NULL;
	IDF_URL    *idf_url = NULL;
	IDF_HEADER *idf_header = NULL;
	IDF_HTTP_REF *idf_http_ref = NULL;
	IDF_HTTP_HDR *idf_http_hdr = NULL;
	IDF_HTTP_AGENT *idf_http_agent = NULL;
	IDF_HTTP *idf_http = NULL;
		
	if(bit_position < IDF_MAP_SPECAIL_BITMAP || bit_position >= IDF_BITMAP_NUM || NULL == idf_info || NULL == flag)//参数检查
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	*flag = R_YES; //默认情况下，需要继续处理
	if(IPPROTO_TCP == idf_info->l4_type)//根据bit_position 获取具体的规则
		idf_rule = (T_IDF_RULE *)g_tcp_bit_map.bit_map[bit_position];
	else
		idf_rule = (T_IDF_RULE *)g_udp_bit_map.bit_map[bit_position];
	if(STRING == idf_rule->type)//string规则
	{
		idf_string = (IDF_STRING *)idf_rule;
		idf_header = idf_string->idf_header;
	}
	else if(URL == idf_rule->type)//url规则
	{
		idf_url = (IDF_URL *)idf_rule;
		idf_header = idf_url->idf_header;
	}
	else if(HTTP_REF == idf_rule->type)
	{
		idf_http_ref = (IDF_HTTP_REF *)idf_rule;
		idf_header = idf_http_ref->idf_header;
	}
	else if(HTTP_HDR == idf_rule->type)
	{

		idf_http_hdr = (IDF_HTTP_HDR *)idf_rule;
		idf_header = idf_http_hdr->idf_header;
	}
	else if(HTTP_AGENT == idf_rule->type)
	{
		idf_http_agent = (IDF_HTTP_AGENT *)idf_rule;
		idf_header = idf_http_agent->idf_header;
	}
	else if(HTTP == idf_rule->type)
	{
		idf_http = (IDF_HTTP*)idf_rule;
		idf_header = idf_http->idf_header;
	}
	else
	{
		log_message(LOG_ERROR, "%s: Type error.\n", __func__);
		return R_ERROR;
	}
	proc_idf_header(idf_header, idf_info, flag);
	return R_OK;
}
/*====================================================
函数名: proc_idf_header
功能:   从规则头处理
入参:  bit_position:  位图中的位置值
             *idf_info:  检查内容
出参:   *flag :            不需要继续处理 R_NO
                                   需要继续处理      R_YES
返回值:  R_OK, R_ERROR
作者:dingdong
时间:2013-11
说明: 
======================================================*/
INT32 proc_idf_header(IDF_HEADER *idf_header, IDF_INFO *idf_info, UINT8 *flag)
{
	UINT8 temp_flag = 0;
	if(NULL == idf_header || NULL == idf_info || NULL == flag)
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	*flag = R_YES;
	if(R_OK != check_idf_header(idf_header, idf_info, &temp_flag))
	{
		log_message(LOG_ERROR, "%s: check_idf_header return R_ERROR.\n", __func__);
		return R_ERROR;
	}
	if(R_YES == temp_flag)//需要沿规则走
	{
		if(R_OK != proc_idf_rule(idf_header->idf_rule, idf_info, idf_header->proto_id, &temp_flag))
		{
			log_message(LOG_ERROR, "%s: proc_idf_rule return R_ERROR.\n", __func__);
			return R_ERROR;
		}
		if(R_YES == temp_flag)//匹配成功
		{
			if(R_OK != proc_state(idf_header, idf_info, flag))
			{
				log_message(LOG_ERROR, "%s: proc_state return R_ERROR.\n", __func__);
				return R_ERROR;
			}
		}	
	}
	return R_OK;
}
/*====================================================
函数名: proc_idf
功能:   从规则获取协议号
入参:  *idf_info:  检查内容
              *tree_root: 规则树的根节点
出参:   
返回值:  R_OK, R_ERROR
作者:dingdong
时间:2013-11
说明: 
======================================================*/
INT32 proc_idf(IDF_INFO *idf_info,IDF_TREE_NODE *tree_root)
{
	UINT8 flag = 0;
	if(NULL == idf_info || NULL == tree_root)//参数检查
	{	
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	memset(idf_info->bitmap, 0, IDF_MAX_BITMAP_LEN);//先全部置0， 以防止前面的结果对后面的操作有影响
    if(idf_info->l5_len > 0 && idf_info->l5 != NULL && g_acsm != NULL) //内容判断 
    {     
        acsmSearch (g_acsm, idf_info->l5, idf_info->l5_len, MatchFound, idf_info); //多模匹配
    }
	//多模匹配后， 首先进行多模匹配结果处理
	if(R_OK != proc_ac_match(idf_info, &flag))
	{
		log_message(LOG_ERROR,  "%s: proc_ac_match return R_ERROR.\n", __func__);
		return R_ERROR;
	}
	if(R_YES == flag)//需要再处理
	{
		if(R_OK != proc_idf_tree(idf_info, tree_root))
		{
			log_message(LOG_ERROR, "%s: proc_idf_tree return R_ERROR.\n", __func__);
			return R_ERROR;
		}
	}
	return R_OK;
}
/*====================================================
函数名: proc_idf_tree
功能:   从规则树中获取结果
入参:  *idf_info:  检查内容
              *tree_root: 规则树的根节点
出参:   
返回值:  R_OK, R_ERROR
作者:dingdong
时间:2013-11
说明: 
======================================================*/
INT32 proc_idf_tree(IDF_INFO *idf_info, IDF_TREE_NODE *tree_root)
{
	IDF_HEADER *idf_header = NULL;
	UINT8 flag = 0;
	if(NULL == idf_info || NULL == tree_root)
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	if(R_OK != get_idf_header(tree_root, &idf_header, idf_info->l5_len))// 获取规则头
	{
		log_message(LOG_ERROR, "%s: get_idf_header return R_ERROR.\n", __func__);
		return R_ERROR;
	}
	while(NULL != idf_header)//获取成功
	{
		if(R_OK != proc_idf_header(idf_header, idf_info, &flag))//处理
		{
			log_message(LOG_ERROR, "%s: proc_idf_header return R_ERROR.\n", __func__);
			return R_ERROR;
		}
		if(R_YES != flag)
			break;
		else
			idf_header = idf_header->next;
	}
	return R_OK;
}

/*====================================================
函数名: init_port_ip_tbl
功能:   初始化PORT 、IP对应表
入参:   
出参:
返回值:  R_OK, R_ERROR
作者:
时间:2013-11
说明:
======================================================*/
INT32  init_port_ip_tbl(IDF_PORT_IP_MAP_TBL **port_ip_tbl)  
{
    int i = 0;
	IDF_PORT_IP_MAP_TBL *temp = NULL;

	if (NULL == port_ip_tbl)
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	
    if(NULL == (temp = i_calloc(sizeof(IDF_PORT_IP_MAP_TBL), sizeof(INT8), I_IDF, 0)))
    {
    	log_message(LOG_ERROR, "%s: No memory.\n", __func__);
		return R_ERROR;
    }//申请内存
    pthread_rwlock_init(&temp->lock, NULL);//初始化锁
    if(NULL == (temp->free_node = i_calloc(sizeof(IDF_IP_PROTO_NODE) , IDF_PORT_IP_MAX_NUM, I_IDF, 0)))
    {
    	log_message(LOG_ERROR, "%s: No memory.\n", __func__);
		i_free(port_ip_tbl);//释放前面申请的内存
		return R_ERROR;
    }//申请内存
    temp->store_address = temp->free_node;  //用于释放内存
    temp->free_node_num = IDF_PORT_IP_MAX_NUM;
    for (i = 0; i < (IDF_PORT_IP_MAX_NUM - 1); i++) //将数组串成链表
    {
        temp->free_node[i].next = &(temp->free_node[i + 1]);
    }

	*port_ip_tbl = temp;
    return R_OK;
}


/*====================================================
函数名: get_port_ip_proto_id
功能:   判断source或dest ip是否在PORT、IP对应表中
入参:    *idf_info : 待检测数据的结构体
                type: 需检查的IP类型， 取值为IDF_TYPE_SOURCE 和
                       IDF_TYPE_DEST
出参:  *flag: R_NO表示找到协议号，不继续查找
                R_YES表示未找到, 继续查找
返回值:  R_OK, R_ERROR
作者:
时间:2013-11
说明:
======================================================*/
INT32  get_port_ip_proto_id(IDF_INFO * idf_info,UINT8 type, UINT8 *flag, UINT8 is_ftp)       
{
	IDF_IP_ADDRESS ip = {0};
	IDF_IP_PROTO_NODE *node = NULL;
	UINT16 port = 0;
	struct in_addr temp_addr = {0};
	IDF_PORT_IP_MAP_TBL *port_ip_tbl = NULL;
	
	if(NULL == idf_info || NULL == flag 
		|| (type != IDF_TYPE_DEST && type != IDF_TYPE_SOURCE 
		&& type != IDF_TYPE_SPORT_DIP && type!= IDF_TYPE_DPORT_SIP))
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	*flag = R_YES;
	if (SET_FLAG == is_ftp)
	{
		port_ip_tbl = g_ftp_port_ip_tbl;
	}
	else
	{
		port_ip_tbl = g_port_ip_tbl;
	}
	
	if(IDF_TYPE_SOURCE == type)//根据type值获取相应的port 和ip
	{
		ip = idf_info->sip;
		port = idf_info->sport;
	}
	else if(IDF_TYPE_DEST == type)
	{
		ip = idf_info->dip;
		port = idf_info->dport;
	}
	else if(IDF_TYPE_DPORT_SIP == type)
	{
		ip = idf_info->sip;
		port = idf_info->dport;
	}
	else
	{
		ip = idf_info->dip;
		port = idf_info->sport;
	}
    pthread_rwlock_rdlock(&port_ip_tbl->lock);//锁住
    node = port_ip_tbl->node_index[port];//在对应的桶中查找
    while (NULL != node) //在链表中查找
    { 
        if ((node->ip.ip_type == ip.ip_type) && 0 == memcmp(&node->ip.addr, &ip.addr, node->ip.ip_type == IDF_IPV4 ? 4 : 16))//是否相等 
        {
        	idf_info->proto_id = node->proto_id;
			*flag = R_NO;
			gettimeofday(&(node->time), 0);
            break;
        }   
        node = node->next;
    }

    pthread_rwlock_unlock(&port_ip_tbl->lock);//解锁
	
	temp_addr = ip.ip4_addr;
	temp_addr.s_addr = htonl(temp_addr.s_addr);
	if (R_NO == *flag)
    {
    	if (0 == debug_switch)
    	{
    		return R_OK;
    	}
    	if (IDF_TYPE_SOURCE == type)
    	{
    		print_idf_rule("sip + sport : port: %d, ip:%s , f_apptype = %d \n", htons(port), inet_ntoa(temp_addr),idf_info->proto_id);
    	}
    	else if(IDF_TYPE_DEST == type)
    	{
    		print_idf_rule("dip + dport: port: %d, ip:%s , f_apptype = %d \n", htons(port), inet_ntoa(temp_addr),idf_info->proto_id);
    	}
		else if(IDF_TYPE_DPORT_SIP == type)
		{
			print_idf_rule("sip + dport : port: %d, ip:%s , f_apptype = %d \n", htons(port), inet_ntoa(temp_addr),idf_info->proto_id);
		}
		else
		{
			print_idf_rule("dip + sport : port: %d, ip:%s , f_apptype = %d \n", htons(port), inet_ntoa(temp_addr),idf_info->proto_id);
		}
    }
    return R_OK;
}

/*====================================================
函数名: do_port_ip_tbl_scan
功能:  实际 执行port ip 扫描
入参:   IDF_PORT_IP_MAP_TBL *port_ip_tbl 
出参:  
返回值:  
作者:
时间:2014-10
说明: 对入参包含的结构体进行操作
======================================================*/
void do_port_ip_tbl_scan(IDF_PORT_IP_MAP_TBL *port_ip_tbl)
{
	INT32 i = 0 , j = 0;
    IDF_IP_PROTO_NODE *pip = NULL, *pip_prev = NULL, *temp_pip = NULL;
	struct timeval t_v = {0};
	
	if (NULL == port_ip_tbl)
	{
		return;
	}

	gettimeofday(&t_v, 0);
    pthread_rwlock_wrlock(&port_ip_tbl->lock);//全锁住
    for (i = 0; i < IDF_PORT_NUM; i++) //一个一个桶操作
    {
    	pip = port_ip_tbl->node_index[i];
        pip_prev = NULL;
        while (pip) //循环访问桶下的链表
        {
            if(t_v.tv_sec - pip->time.tv_sec > IDF_PORT_IP_MAX_TIME || t_v.tv_sec < pip->time.tv_sec)
            {
                temp_pip = pip;
				pip = pip->next;
				if(NULL == pip_prev)
					port_ip_tbl->node_index[i] = pip;
				else
					pip_prev->next = pip;
				temp_pip->next = port_ip_tbl->free_node;
				port_ip_tbl->free_node = temp_pip;
				(port_ip_tbl->free_node_num)++;
             }
			else
			{
				pip_prev = pip;
				pip = pip->next;
			}
        }

     }
     pthread_rwlock_unlock(&port_ip_tbl->lock);//解锁
}
/*====================================================
函数名: port_ip_tbl_scan
功能:   扫描PORT 、IP对应表
入参:   
出参:
返回值:   R_OK, R_ERROR
作者:
时间:  2013-11
说明: 启动独立的线程检查
======================================================*/
void *port_ip_tbl_scan(void *_arg)
{
    if (NULL == g_port_ip_tbl || NULL == g_port_ip_tbl->free_node
		|| NULL == g_ftp_port_ip_tbl || NULL == g_ftp_port_ip_tbl->free_node) //检查
    {
    	log_message(LOG_ERROR, "%s: g_port_ip_tbl or g_port_ip_tbl->free_node is NULL.\n", __func__);
        return NULL;
    }

    while (1) //线程死循环定时检查
    {
    	do_port_ip_tbl_scan(g_port_ip_tbl);
		do_port_ip_tbl_scan(g_ftp_port_ip_tbl);
        sleep(60);  //定时检查
    }
    return NULL;
}
/*====================================================
函数名: get_idf_header
功能:   在规则树中根据长度值找到对应的规则头链表
入参:   *tree_root: 规则树的根节点
               len: 报文的长度值
出参:  **output_header:  规则头链表的头指针
返回值:  R_OK, R_ERROR
作者:
时间:2013-11
说明: 
======================================================*/
INT32 get_idf_header(IDF_TREE_NODE *tree_root, IDF_HEADER **output_header, INT32 len)
{
	IDF_TREE_NODE  *node = NULL;
	IDF_TREE_NODE  *pre_node = NULL;
	if(NULL == tree_root || NULL == output_header || 0 > len)// 参数检查
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n",__func__);
		return R_ERROR;
	}
	node = tree_root;
	pre_node = tree_root;
	while(NULL != node)//在树中找到相应的叶子节点
	{
		if(len <= node->len)
		{
			pre_node = node;
			node = node->left_small;
		}
		else
		{
			pre_node = node;
			node = node->right_big;
		}
	}
	if(len <= pre_node->len)//在节点中判断使用左链表还是右链表
		*output_header = pre_node->left_header;
	else
		*output_header = pre_node->right_header;
	return R_OK;
}

/*====================================================
函数名: check_idf_header
功能:   检查规则头节点是否需要处理检测内容
入参:   *header: 规则头节点
               *idf_info: 检查内容
出参:   *flag :            不需要处理 R_NO
                                   需要处理      R_YES
返回值:  R_OK, R_ERROR
作者:
时间:2013-11
说明: 
======================================================*/
inline INT32 check_idf_header(IDF_HEADER *header, IDF_INFO *idf_info, UINT8 *flag)
{
	INT32 len = 0;
	if(NULL == header || NULL == idf_info || NULL == flag)//参数检查
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n",__func__);
		return R_ERROR;
	}
	*flag = R_NO;
	len = idf_info->l5_len;
	if(0 !=  header->bit_used_num)//如果只有一项，则必须走规则， 如果大于1项， 需判断相应的所有规则都匹配上
	{
		if(R_OK != check_idf_bit_position(header, idf_info, flag))//在检查时， 将相应的位需要值为0
		{
			log_message(LOG_ERROR, "%s: check_idf_bit_position return R_ERROR.\n");
			return R_ERROR;
		}
		if(R_YES != *flag)
		return R_OK;
	}
	*flag = R_NO;
	if(0 != header->payload_len)//如果规则中 的payloadlength有效
	{
		if(header->payload_len < 0)
		{
			if((len + header->payload_len) < 0)// 报文长度需大于|payloadlength| 才处理
				return R_OK;
		}
		else if( len != header->payload_len)//报文需相等才处理
			return R_OK;
	}
	if(len < header->min_len)//payloadlength无效时， 报文长度小于规则中的最小值， 不处理
		return R_OK;

     //---------------------------新增加的判断----------------------------------------
	if(0 != CHECK_BIT(idf_info->state, IDF_STATE_POSSIBLE))//已识别为可能值
	{
		if(SET_FLAG == header->is_pos)//只需查看规则为可能值的情况， 不含有可能值时， 其优先级一定要高
		{
			if(!(0 != CHECK_BIT(idf_info->state, IDF_IS_PORT) && 1 == idf_info->store_priority && 1 == header->priority))
			{
				if(header->priority <= idf_info->store_priority)//其优先级比保存的低
				return R_OK;
			}
		}
	}
	else//还没有识别或者识别了确定的协议号， 但优先级不等于1
	{
		if(SET_FLAG == header->is_pos)
		{
			if(0 != idf_info->store_priority)
				return R_OK;
		}
		else
		{
			if(idf_info->store_priority <= header->priority && 0 != idf_info->store_priority)
				return R_OK;
		}
	}
	if(SET_FLAG == header->is_statu)
	{
		if(SET_FLAG == header->is_final_statu && 0 != CHECK_BIT(idf_info->state, IDF_STATE_CURRENT_STATUS))//避免一个报文匹配两个规则
			return R_OK;
		if(0 != strcmp(idf_info->status, header->pre_statu))
			return R_OK;	
	}
	//----------------------------------------------------------------------------------------
	//判断是树中的规则头还是单独提出的链表中的规则头
	*flag = R_YES;//处理
	return R_OK;
}
/*====================================================
函数名: proc_state_comm
功能:   匹配后的状态处理, 处理普通规则(非状态机) 
入参:    *header: 规则节点， 对应XML中type字段之间的内容，
                           内有规则链表
                *idf_info: 待检测数据的结构体
出参:  *flag:  表示是否沿规则节点链表继续运行
                        继续运行  R_YES
                        不继续运行   R_NO        
返回值:  无
作者: dingdong
时间:2014-4-12
说明:  
======================================================*/
inline void proc_state_comm(IDF_HEADER *header, IDF_INFO *idf_info, UINT8 *flag)
{
	if(NULL == header || NULL == idf_info || NULL == flag)
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n", __func__);
		return;
	}
	if(SET_FLAG == header->is_pos)
		idf_info->state = SET_BIT(idf_info->state, IDF_STATE_POSSIBLE);
	else
		idf_info->state = RESET_BIT(idf_info->state, IDF_STATE_POSSIBLE);
	
	idf_info->s_proto_id = header->proto_id;
	idf_info->store_priority = header->priority;
	if(SET_FLAG == header->is_pos || header->priority != 1)
		*flag = R_YES;
	else
		*flag = R_NO;
	if(SET_FLAG != header->is_pos)
		idf_info->proto_id = idf_info->s_proto_id;
	idf_info->state = RESET_BIT(idf_info->state, IDF_IS_PORT);
	
#ifdef RULE_RATE_TEST
	idf_info->rule_use = header->rule_use;
	idf_info->classfy_rule = header->classfy_rule;
#endif

	return;
}
/*====================================================
函数名: proc_state_status_comm
功能:   匹配后的状态处理, 处理状态机中非最终状态
               规则
入参:    *header: 规则节点， 对应XML中type字段之间的内容，
                           内有规则链表
                *idf_info: 待检测数据的结构体
出参:  *flag:  表示是否沿规则节点链表继续运行
                        继续运行  R_YES
                        不继续运行   R_NO        
返回值:  无
作者: dingdong
时间:2014-4-12
说明:  
======================================================*/
inline void proc_state_status_comm(IDF_HEADER *header, IDF_INFO *idf_info, UINT8 *flag)
{
	if(NULL == header || NULL == idf_info || NULL == flag)
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n", __func__);
		return;
	}
	idf_info->state = SET_BIT(idf_info->state, IDF_STATE_CURRENT_STATUS);
	idf_info->state = SET_BIT(idf_info->state, IDF_STATE_USE_STATUS);
	if(SET_FLAG == header->is_pos)
		idf_info->state = SET_BIT(idf_info->state, IDF_STATE_STATUS_POSSIBLE);
	snprintf(idf_info->status, IDF_MAX_STATU_LEN, header->statu);
	idf_info->terminal_id = header->proto_id;
	*flag = R_YES;
	
	return;
}
/*====================================================
函数名: proc_state_status_final
功能:   匹配后的状态处理, 处理状态机中最终状态
               规则
入参:    *header: 规则节点， 对应XML中type字段之间的内容，
                           内有规则链表
                *idf_info: 待检测数据的结构体
出参:  *flag:  表示是否沿规则节点链表继续运行
                        继续运行  R_YES
                        不继续运行   R_NO        
返回值:  无
作者: dingdong
时间:2014-4-12
说明:  
======================================================*/
inline void proc_state_status_final(IDF_HEADER *header, IDF_INFO *idf_info, UINT8 *flag)
{
	if(NULL == header || NULL == idf_info || NULL == flag)
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n", __func__);
		return;
	}
	snprintf(idf_info->status, IDF_MAX_STATU_LEN, header->statu);
	if(0 != CHECK_BIT(idf_info->state, IDF_STATE_STATUS_POSSIBLE))
	{
		idf_info->state = SET_BIT(idf_info->state, IDF_STATE_POSSIBLE);
	}
	else
		idf_info->state = RESET_BIT(idf_info->state, IDF_STATE_POSSIBLE);
	idf_info->s_proto_id = header->proto_id;
	idf_info->store_priority = header->priority;
	if(SET_FLAG == header->is_pos || header->priority != 1)
		*flag = R_YES;
	else
		*flag = R_NO;
	if(SET_FLAG != header->is_pos)
		idf_info->proto_id = idf_info->s_proto_id;

	idf_info->state = RESET_BIT(idf_info->state, IDF_STATE_CURRENT_STATUS);
	idf_info->state = RESET_BIT(idf_info->state, IDF_STATE_STATUS_POSSIBLE);
	idf_info->state = RESET_BIT(idf_info->state, IDF_STATE_USE_STATUS);
	idf_info->state = RESET_BIT(idf_info->state, IDF_IS_PORT);

#ifdef RULE_RATE_TEST
	idf_info->rule_use = header->rule_use;
	idf_info->classfy_rule = header->classfy_rule;
#endif
	return;
}
/*====================================================
函数名: proc_state
功能:   匹配后的状态处理 
入参:    *header: 规则节点， 对应XML中type字段之间的内容，
                           内有规则链表
                *idf_info: 待检测数据的结构体
                
出参:  *flag:  表示是否沿规则节点链表继续运行
                        继续运行  R_YES
                        不继续运行   R_NO        
返回值:  R_OK, R_ERROR
作者:
时间:2013-11
说明:  关于priotiry， 有些定义不清， 例如， 如果在匹配
规则时， 先匹配上priority为1的可能协议号， 再继续匹配
时， 匹配上priority为2的可能协议号， 此时的s_proto_id是否
应该修改? 按照优先级， 值越小， 其优先级越大， 在
这种情况下不应该修改s_proto_id, 但按照现有的规则， 修改
s_proto_id更合适些。典型的例子是browsing_app/httpport.xml中的
规则和search_app/baidu.xml中的规则。
======================================================*/
INT32 proc_state(IDF_HEADER *header, IDF_INFO *idf_info,  UINT8 *flag)
{
	if(NULL == header || NULL == idf_info  || NULL == flag)//参数检查
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n",__func__);
		return R_ERROR;
	}
	*flag = R_NO;// 初始值设置
	if(SET_FLAG == header->is_statu)
	{
		if(SET_FLAG == header->is_final_statu)
			proc_state_status_final(header, idf_info, flag);
		else
			proc_state_status_comm(header, idf_info, flag);
	}
	else
		proc_state_comm(header, idf_info, flag);
	return R_OK;
}
/*====================================================
函数名: proc_idf_rule
功能:   具体的规则链表匹配
入参:    *list_header: 规则链表的开始节点
                *idf_info : 待检测数据的结构体
                proto_id: 规则链表所在的规则头节点中的协议号
出参:  *output_flag:  
                       匹配成功:  R_YES
                       匹配不通过:   R_NO
返回值:  R_OK, R_ERROR
作者:
时间:2013-11
说明: 
======================================================*/
INT32 proc_idf_rule(void *list_header,  IDF_INFO *idf_info, UINT32 proto_id, UINT8 *output_flag)
{
	T_IDF_RULE  *idf_rule = NULL;
	void *list_node = NULL;
	IDF_TYPE type = 0;
	UINT8 flag = 0;
	if(NULL == idf_info || NULL == output_flag)//参数检查
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n",__func__);
		return R_ERROR;
	}
	if(NULL == list_header)
	{
		return R_OK;
	}
	list_node = list_header;
	while(NULL != list_node)//遍历链表
	{
		idf_rule  = (T_IDF_RULE *)list_node;
		type = idf_rule->type;
		if(type!=PORT && type!=LENGTH && type!=STRING && type != IPV6 && idf_info->l5_len <= 0)
		{
			flag = R_NO;
			break;
		}
		switch(type)
		{
			case CHAR:
				if(R_OK != do_char_check(idf_info, (IDF_CHAR *)list_node, &flag))
				{
					log_message(LOG_ERROR, "%s: do_char_check return R_ERROR.\n", __func__);
					return R_ERROR;
				}
				break;
			case STRING:
				if(R_OK != do_string_check(idf_info, (IDF_STRING *)list_node, &flag))
				{
					log_message(LOG_ERROR, "%s: do_string_check return R_ERROR.\n", __func__);
					return R_ERROR;
				}
				break;
			case CONTENT_CONTENT:
				if(R_OK != do_content_content_check(idf_info, (IDF_CONTENT_CONTENT *)list_node, &flag))
				{
					log_message(LOG_ERROR, "%s: do_content_content_check return R_ERROR.\n", __func__);
					return R_ERROR;
				}
				break;
			case HTTP_CONTENT_LENTH:
				if(R_OK != do_http_content_length_check(idf_info, (IDF_HTTP_CONTENT_LENGTH *)list_node, &flag))
				{
					log_message(LOG_ERROR, "%s: do_http_content_length_check return R_ERROR.\n", __func__);
					return R_ERROR;
				}
				break;
			case CONTENT_LENTH:
				if(R_OK != do_content_length_check(idf_info, (IDF_CONTENT_LENGTH *)list_node, &flag))
				{
					log_message(LOG_ERROR, "%s: do_content_length_check return R_ERROR.\n", __func__);
					return R_ERROR;
				}
				break;
			case BUFFER_ADD:
				if(R_OK != do_buffer_add(idf_info, (IDF_BUFFER_ADD *)list_node))
				{
					log_message(LOG_ERROR, "%s: do_buffer_add return R_ERROR.\n", __func__);
					return R_ERROR;
				}
				flag = R_YES;
				break;
			case BUFFER_JUDGE:
				if(R_OK != do_buffer_judge(idf_info, (IDF_BUFFER_JUDGE *)list_node, &flag))
				{
					log_message(LOG_ERROR, "%s: do_buffer_judge return R_ERROR.\n", __func__);
					return R_ERROR;
				}
				break;
			case BUFFER_SAVE:
				if(R_OK != do_buffer_save(idf_info, (IDF_BUFFER_SAVE *)list_node, &flag))
				{
					log_message(LOG_ERROR, "%s: do_buffer_save return R_ERROR.\n", __func__);
					return R_ERROR;
				}
				break;
			case URL:
				if(R_OK != do_url_judge(idf_info, (IDF_URL *)list_node, &flag))
				{
					log_message(LOG_ERROR, "%s: do_url_judge return R_ERROR.\n", __func__);
					return R_ERROR;
				}
				break;
			case ADD_SOURCE_PORT:
				if(R_OK != do_addport(idf_info, proto_id,IDF_TYPE_SOURCE, RESET_FLAG, 0))
				{
					log_message(LOG_ERROR, "%s: do_addport return R_ERROR.\n", __func__);
					return R_ERROR;
				}
				flag = R_YES;
				break;
			case ADD_DEST_PORT:
				if(R_OK != do_addport(idf_info, proto_id,IDF_TYPE_DEST, RESET_FLAG, 0))
				{
					log_message(LOG_ERROR, "%s: do_adddestport return R_ERROR.\n", __func__);
					return R_ERROR;
				}
				flag = R_YES;
				break;
			case ADD_SPORT_DIP:
				if(R_OK != do_addport(idf_info, proto_id,IDF_TYPE_SPORT_DIP, RESET_FLAG, 0))
				{
					log_message(LOG_ERROR, "%s: do_addsportdip return R_ERROR.\n", __func__);
					return R_ERROR;
				}
				flag = R_YES;
				break;
			case ADD_DPORT_SIP:
				if(R_OK != do_addport(idf_info, proto_id,IDF_TYPE_DPORT_SIP, RESET_FLAG, 0))
				{
					log_message(LOG_ERROR, "%s: do_adddportsip return R_ERROR.\n", __func__);
					return R_ERROR;
				}
				flag = R_YES;
				break;
			case PORT:
				if(R_OK != do_port_check(idf_info, (IDF_PORT *)list_node, &flag))
				{
					log_message(LOG_ERROR, "%s: do_port_check return R_ERROR.\n", __func__);
					return R_ERROR;
				}
				break;
			case LENGTH:
				if(R_OK != do_length_check(idf_info, (IDF_LENGTH *)list_node, &flag))
				{
					log_message(LOG_ERROR, "%s: do_length_check return R_ERROR.\n", __func__);
					return R_ERROR;
				}
				break;
			case HTTP_REF:
				if(R_OK != do_http_ref_check(idf_info, (IDF_HTTP_REF *)list_node, &flag))
				{
					log_message(LOG_ERROR, "%s: do_http_ref_check return R_ERROR.\n", __func__);
					return R_ERROR;
				}
				break;
			case HTTP_HDR:
				if(R_OK != do_http_hdr_check(idf_info, (IDF_HTTP_HDR *)list_node, &flag))
				{
					log_message(LOG_ERROR, "%s: do_http_hdr_check return R_ERROR.\n", __func__);
					return R_ERROR;
				}
				break;
			case HTTP_AGENT:
				if(R_OK != do_http_agent_check(idf_info, (IDF_HTTP_AGENT *)list_node, &flag))
				{
					log_message(LOG_ERROR, "%s: do_http_agent_check return R_ERROR.\n", __func__);
					return R_ERROR;
				}
				break;
			case HTTP:
				if(R_OK != do_http_check(idf_info, (IDF_HTTP *)list_node, &flag))
				{
					log_message(LOG_ERROR, "%s: do_http_agent_check return R_ERROR.\n", __func__);
					return R_ERROR;
				}
				break;
			case IPV6:
				if(R_OK != do_ipv6_check(idf_info, (IDF_IPV6_PROTO_NODE *)list_node, &flag))
				{
					log_message(LOG_ERROR, "%s: do_ipv6_check return R_ERROR.\n", __func__);
					return R_ERROR;
				}
				break;
			default:
				log_message(LOG_ERROR, "%s: cluster_type is wrong.\n", __func__);
				return R_ERROR;
				break;
		}
		if(R_YES != flag)
			break;
		else//指向下一节点
		{
			list_node = idf_rule->next;
		}
	}
	*output_flag  = flag;
	return R_OK;
}
/*====================================================
函数名: get_idf_proto_id
功能:   从规则树获取协议号
入参:   *idf_info : 待检测数据的结构体               
出参:              
返回值:  R_OK, R_ERROR
作者:
时间:2013-11
说明: 
======================================================*/
INT32  get_idf_proto_id(IDF_INFO *idf_info)  
{  
	IDF_TREE_NODE *tree_root = NULL;
	if(NULL == idf_info )//参数检查
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n",__func__);
		return R_ERROR;
	}
    if (NULL == g_idf_tree)//规则树检查
    {
    	log_message(LOG_ERROR, "%s: idf_tree is NULL.\n", __func__);
        return R_ERROR;
    }
    if (0 == idf_info->status[0])//初始化
    	snprintf(idf_info->status, IDF_MAX_STATU_LEN, "NO_STATUS");

    if (IPPROTO_TCP == idf_info->l4_type) //选择树
    	tree_root = g_idf_tree->tcp_tree_root;
	else if(IPPROTO_UDP == idf_info->l4_type)
		tree_root = g_idf_tree->udp_tree_root;
	else
	{//出错
		log_message(LOG_ERROR, "%s: idf_info->l4type is wrong. l4type:%d.\n", __func__, idf_info->l4_type);
		return R_ERROR;
	}
	if(R_OK != proc_idf(idf_info, tree_root))//获取协议号
	{
		log_message(LOG_ERROR, "%s: check_cluster_group return R_ERROR.\n", __func__);
		return R_ERROR;
	}
    return R_OK;
}

/*====================================================
函数名: get_port_proto_id
功能:   根据端口获取协议号
入参:   *idf_info : 待检测数据的结构体
出参:   *flag: R_NO表示找到协议号，不继续查找
                R_YES表示未找到, 继续查找
返回值:  R_OK, R_ERROR
作者:
时间:2013-11
说明: 
======================================================*/
INT32  get_port_proto_id(IDF_INFO *idf_info, UINT8 *flag)
{
    UINT32 sport = 0;
	UINT32 dport = 0;
	UINT32  *port  = NULL;
	UINT8  *port_is_pos = NULL;
	if(NULL == idf_info  || NULL == flag)//参数检查
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n",__func__);
		return R_ERROR;
	}
	*flag = R_YES;
    if(ntohs(idf_info->sport) < ntohs(idf_info->dport)) //先用最小端口判断
    {
        sport = idf_info->sport;  
        dport = idf_info->dport;
    }
    else 
    {
        sport = idf_info->dport;  
        dport = idf_info->sport;
    } 
	if (IPPROTO_TCP == idf_info->l4_type) //确定使用的数组
	{
		port = g_port_proto_tbl.tcp_port;
		port_is_pos = g_port_proto_tbl.tcp_port_is_pos;
	}
	else
	{
		port = g_port_proto_tbl.udp_port;
		port_is_pos = g_port_proto_tbl.udp_port_is_pos;
	}
	if(0 != port[htons(sport)])//是否是有效的协议号
	{
		if(0 != port_is_pos[htons(sport)] || (htons(sport) >= 1024 && htons(sport) != 3306))//如果端口大于1024, 都需设置为可能协议
		{
			idf_info->s_proto_id = port[htons(sport)];
			idf_info->store_priority = 1;  //端口规则的可能值， 优先级设置为1
			idf_info->state = SET_BIT(idf_info->state, IDF_STATE_POSSIBLE);
			idf_info->state = SET_BIT(idf_info->state, IDF_IS_PORT);
#ifdef RULE_RATE_TEST
			bit_set_value(&idf_info->rule_use, PORT_RATE);
			idf_info->classfy_rule = CLASSFY_PORT;
#endif	
		}
		else
		{
			idf_info->proto_id = port[htons(sport)];
			*flag = R_NO;
#ifdef RULE_RATE_TEST
			bit_set_value(&idf_info->rule_use, PORT_RATE);
			idf_info->classfy_rule = CLASSFY_PORT;
#endif	

			if (0 == debug_switch)
			{
				return R_OK;
			}
			print_idf_rule("port: %d, f_apptype = %d\n",htons(sport),idf_info->proto_id);
		}
	}
	else if(0 != port[htons(dport)])
	{
		if(0 != port_is_pos[htons(dport)] || (htons(dport) >= 1024  && htons(dport) != 3306))
		{
			idf_info->s_proto_id = port[htons(dport)];
			idf_info->store_priority = 1;
			idf_info->state = SET_BIT(idf_info->state, IDF_STATE_POSSIBLE);
			idf_info->state = SET_BIT(idf_info->state, IDF_IS_PORT);
#ifdef RULE_RATE_TEST
			bit_set_value(&idf_info->rule_use, PORT_RATE);
			idf_info->classfy_rule = CLASSFY_PORT;
#endif	

		}
		else
		{
			idf_info->proto_id = port[htons(dport)];
			*flag = R_NO;
#ifdef RULE_RATE_TEST
			bit_set_value(&idf_info->rule_use, PORT_RATE);
			idf_info->classfy_rule = CLASSFY_PORT;
#endif

			if (0 == debug_switch)
			{
				return R_OK;
			}
			print_idf_rule("port: %d, f_apptype = %d\n",htons(dport),idf_info->proto_id);
		}
	}
	return R_OK;
}
/*====================================================
函数名: print_idf_rule
功能:  打印识别信息
入参:  
出参: 
返回值:  R_OK, R_ERROR
作者:
时间:2013-11
说明: 
======================================================*/
void print_idf_rule(const INT8 *format, ...)
{
	INT8 log_str[G_LOG_LEN] = {0};
	va_list ap;
	get_str_time(log_str, G_LOG_LEN);
	va_start(ap, format);
	vsnprintf(log_str + strlen(log_str), G_LOG_LEN - strlen(log_str), format, ap);
	va_end(ap);
	if(debug_switch != 0)
	{	
		LOCK(&g_print_lock);
		fprintf(g_fp, "%s", log_str);
		fflush(g_fp);
		UNLOCK(&g_print_lock);
	}
}
/*====================================================
函数名: proc_first_packet
功能:  处理流中的第一个报文
入参:   *idf_info : 待检测数据的结构体
出参: 
返回值:  R_OK, R_ERROR
作者:
时间:2013-11
说明: 
======================================================*/
INT32 proc_first_packet(IDF_INFO *idf_info, UINT8 *flag)
{
	UINT32 proto_id = 0;
	if(NULL == idf_info)//参数检查
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n",__func__);
		return R_ERROR;
	}
	*flag = R_YES;
	if (0 == idf_info->pkt_count)
	{
		init_pkt_proto(idf_info);//初始?
	
		if(R_OK != get_ip_hash_proto_id(idf_info, g_ip_hash_tbl, flag,SET_FLAG))
		{
			log_message(LOG_ERROR, "%s: get_ip_hash_proto_id return R_ERROR.\n", __func__);
			return R_ERROR;
		}
		if(R_YES != *flag)
			return R_OK;
	
		if(R_OK != get_ip_hash_proto_id(idf_info, g_ip_hash_tbl, flag,RESET_FLAG))
		{
			log_message(LOG_ERROR, "%s: get_ip_hash_proto_id return R_ERROR.\n", __func__);
			return R_ERROR;
		}
		if(R_YES != *flag)
			return R_OK;
    }
	if(R_OK != get_port_ip_proto_id(idf_info, IDF_TYPE_SOURCE, flag, RESET_FLAG))
	{
		log_message(LOG_ERROR, "%s: get_port_ip_proto_id return R_ERROR.\n", __func__);
		return R_ERROR;
	}
	if(R_YES != *flag)
	{
#ifdef RULE_RATE_TEST
		bit_set_value(&idf_info->rule_use, ADDPORT_RATE);
		idf_info->classfy_rule = CLASSFY_ADDPORT;
#endif
		return R_OK;
	}

	if(R_OK != get_port_ip_proto_id(idf_info, IDF_TYPE_SOURCE, flag, SET_FLAG))
	{
		log_message(LOG_ERROR, "%s: get_port_ip_proto_id return R_ERROR.\n", __func__);
		return R_ERROR;
	}
	if(R_YES != *flag)
	{
#ifdef RULE_RATE_TEST
		bit_set_value(&idf_info->rule_use, ADDPORT_RATE);
		idf_info->classfy_rule = CLASSFY_ADDPORT;
#endif
		return R_OK;
	}
	
	if(R_OK != get_port_ip_proto_id(idf_info, IDF_TYPE_DEST, flag, RESET_FLAG))
	{
		log_message(LOG_ERROR, "%s: get_port_ip_proto_id return R_ERROR.\n", __func__);
		return R_ERROR;
	}
	if(R_YES != *flag)
	{
#ifdef RULE_RATE_TEST
		bit_set_value(&idf_info->rule_use, ADDOUTPORT_RATE);
		idf_info->classfy_rule = CLASSFY_ADDPORT;
#endif		
		return R_OK;
	}

	if(R_OK != get_port_ip_proto_id(idf_info, IDF_TYPE_DEST, flag, SET_FLAG))
	{
		log_message(LOG_ERROR, "%s: get_port_ip_proto_id return R_ERROR.\n", __func__);
		return R_ERROR;
	}
	if(R_YES != *flag)
	{
#ifdef RULE_RATE_TEST
		bit_set_value(&idf_info->rule_use, ADDOUTPORT_RATE);
		idf_info->classfy_rule = CLASSFY_ADDPORT;
#endif		
		return R_OK;
	}
	
	if(R_OK != get_port_ip_proto_id(idf_info, IDF_TYPE_SPORT_DIP, flag, RESET_FLAG))
	{
		log_message(LOG_ERROR, "%s: get_port_ip_proto_id return R_ERROR.\n", __func__);
		return R_ERROR;
	}
	if(R_YES != *flag)
	{
#ifdef RULE_RATE_TEST
		bit_set_value(&idf_info->rule_use, ADDPORTDIP_RATE);
		idf_info->classfy_rule = CLASSFY_ADDPORT;
#endif	
		return R_OK;
	}
	if(R_OK != get_port_ip_proto_id(idf_info, IDF_TYPE_DPORT_SIP, flag, RESET_FLAG))
	{
		log_message(LOG_ERROR, "%s: get_port_ip_proto_id return R_ERROR.\n", __func__);
		return R_ERROR;
	}
	if(R_YES != *flag)
	{
#ifdef RULE_RATE_TEST
		bit_set_value(&idf_info->rule_use, ADDOUTPORTSIP_RATE);
		idf_info->classfy_rule = CLASSFY_ADDPORT;
#endif	
		return R_OK;
	}
	if (0 == idf_info->pkt_count)
	{
		if(R_OK != get_port_proto_id(idf_info,flag))
		{
			log_message(LOG_ERROR, "%s: get_port_proto_id return R_ERROR.\n", __func__);
			return R_ERROR;
		}
	}
	return R_OK;
}
/*====================================================
函数名: init_pkt_proto
功能:  初始化协议大类
入参:   *idf_info : 待检测数据的结构体
           
出参: 
返回值:  R_OK, R_ERROR
作者:
时间:2013-11
说明: 
======================================================*/
INT32 init_pkt_proto(IDF_INFO *idf_info)
{
	if(NULL == idf_info)//参数检查
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n",__func__);
		return R_ERROR;
	}
	if(0 == idf_info->s_proto_id)
	{
		if(IPPROTO_TCP == idf_info->l4_type)
		{
				idf_info->s_proto_id = IDF_PROTO_TCP;
		}
		else if(IPPROTO_UDP == idf_info->l4_type)
		{
			idf_info->s_proto_id = IDF_PROTO_UDP;
		}
	}
	return R_OK;
}
/*====================================================
函数名: proc_ftp_data
功能:  处理ftp动态端口数据
入参:   *idf_info : 待检测数据的结构体
出参: 
返回值:  R_OK, R_ERROR
作者:
时间:2013-12
说明: 
======================================================*/
inline INT32 proc_ftp_data(IDF_INFO *idf_info)
{
	UINT16 port = 0;
	if(NULL == idf_info->l5  || idf_info->l5_len <= PASV_FTP_MIN_LEN)
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	if(R_OK != get_PASV_ftp_port(idf_info->l5, idf_info->l5_len, &port))
	{
		log_message(LOG_ERROR, "%s: get_PASV_ftp_port return R_ERROR.\n", __func__);
		return R_ERROR;
	}
	if(R_OK != do_addport(idf_info, IDF_PROTO_FTP, IDF_TYPE_SOURCE, SET_FLAG, port))
	{
		log_message(LOG_ERROR, "%s: do_addport return R_ERROR.\n", __func__);
		return R_ERROR;
	}
	if(R_OK != do_addport(idf_info, IDF_PROTO_FTP, IDF_TYPE_DEST, SET_FLAG, port))
	{
		log_message(LOG_ERROR, "%s: do_addport return R_ERROR.\n", __func__);
		return R_ERROR;
	}
	return R_OK;
}
/*====================================================
函数名: idf
功能:  对外接口， 获取协议号
入参:   *idf_info : 待检测数据的结构体
出参: 
返回值:  R_OK, R_ERROR
作者:
时间:2013-11
说明: 
======================================================*/
INT32 idf(IDF_INFO *idf_info)    
{    
	UINT32 proto_id = 0;
	UINT8 debug_result_flag = RESET_FLAG;
	UINT8 str[G_PRINT_LEN] = {0};
	UINT8 flag = 0;
	UINT8 store_status[IDF_MAX_STATU_LEN] = {0};
	INT32 nopayload_count = 0;
    if(NULL == idf_info)//参数检查
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n",__func__);
		return R_ERROR;
	}
    if(idf_info->l5_len > 0)
    {
		idf_info->payload_count++;
    }
    else 
    {
        nopayload_count = idf_info->pkt_count - idf_info->payload_count + 1;
       
    }
	
	if(debug_switch != 0)//增加的调试信息
	{
		if((idf_info->payload_count < IDF_PKT_THRESHOLD/2) && 0 == idf_info->proto_id) 
		{
			debug_result_flag = SET_FLAG;
		}
	}
	if (0 == idf_info->proto_id)
	{
    	if (5 > idf_info->pkt_count) //为流中的第一个报文
    	{  
       	 	if(R_OK != proc_first_packet(idf_info, &flag))
        	{
        		log_message(LOG_ERROR, "%s: proc_first_packet return R_ERROR.\n", __func__);
				return R_ERROR;
        	}
			if(R_YES != flag)
			{
				idf_info->id = idf_info->proto_id;
				goto _end;
			}
    	}
	}
	if(idf_info->l4_type != IPPROTO_TCP && idf_info->l4_type != IPPROTO_UDP)
	{
		goto _end;
	}
	if(554 == htons(idf_info->sport) || 554 == htons(idf_info->dport))
	{
		if(debug_switch != 0)
			debug_result_flag = SET_FLAG;
		
		if (check_payload_first_byte(idf_info->l5, idf_info->l5_len) == R_OK) 
		{
			idf_info->proto_id = IDF_RTP_OVER_RTSP;
		} 
		else 
		{
			idf_info->proto_id = IDF_PROTO_RTSP;
		}
		idf_info->id = idf_info->proto_id;
	}
	if(NULL != idf_info->l5 && idf_info->l5_len > PASV_FTP_MIN_LEN)
	{
		if(0 == memcmp(idf_info->l5, "227 ", 4) || 0 == memcmp(idf_info->l5, "229 ", 4))
		{
			proc_ftp_data(idf_info);
			if(debug_switch != 0)
				debug_result_flag = SET_FLAG;
		}
	}

	if (nopayload_count > IDF_NO_PAYLOAD_COUNT)
    {
        return R_OK;
    }
    if (0 == idf_info->proto_id) //还未识别
    { 
        if (idf_info->payload_count < IDF_PKT_THRESHOLD/2)
        {
        	if(0 != CHECK_BIT(idf_info->state, IDF_STATE_USE_STATUS))//判断是否使用了状态机
        	{
        		if(0 == strlen(idf_info->status))
        		{
        			log_message(LOG_ERROR, "%s: idf_info->state may be wrong, please check it .\n", __func__);
					return R_ERROR;

        		}
        		snprintf(store_status, IDF_MAX_STATU_LEN, idf_info->status);//保存当前已经到达的状态
				idf_info->terminal_id = 0;
			}
			
            if(R_OK != get_idf_proto_id(idf_info))//调用识别函数
            {
            	log_message(LOG_ERROR,"%s: get_proto_id return R_ERROR.\n", __func__);
				idf_info->state = 0;//出错时， 将所有的的状态全清空
				return R_ERROR;
            }

			idf_info->state = RESET_BIT(idf_info->state, IDF_STATE_CURRENT_STATUS);//退出get_idf_proto_id后， IDF_STATE_CURRENT_STATUS位置0
			if(0 !=  CHECK_BIT(idf_info->state, IDF_STATE_USE_STATUS))//判断是否使用了状态机
			{
				if(0 == strcmp(idf_info->status, store_status))//如果状态没有改变， 则状态机失效
				{

					idf_info->state = RESET_BIT(idf_info->state, IDF_STATE_USE_STATUS);
					snprintf(idf_info->status, IDF_MAX_STATU_LEN, "NO_STATUS");
				}
			}

        }  
    }
	idf_info->id = idf_info->proto_id > 0 ? idf_info->proto_id: idf_info->s_proto_id;
	if((IDF_PROTO_TCP == idf_info->id || IDF_PROTO_UDP == idf_info->id) && idf_info->terminal_id != 0)
		idf_info->id = idf_info->terminal_id;
_end:
	if(debug_switch != 0)//增加的调试信息
	{
		if(SET_FLAG == debug_result_flag)
		{
			debug_idf_info(idf_info,  str, G_PRINT_LEN);
			debug_idf_info_result(idf_info, str + strlen(str), G_PRINT_LEN - strlen(str));
			LOCK(&g_print_lock);
				fprintf(g_fp, "%s", str);
				fflush(g_fp);
			UNLOCK(&g_print_lock);
		}
		debug_result_flag = RESET_FLAG;
	}
	return R_OK;
}  


/*====================================================
函数名: init_tree
功能:  初始化树
入参:   node_len: 数组， 树节点中的长度，-1 表示无效
              数组的数目
出参: **tree_root:  构建树以后的树的根节点
返回值:  R_OK, R_ERROR
作者:
时间:2013-11
说明: 
======================================================*/
INT32  init_tree(IDF_TREE_NODE **tree_root, INT32 node_len[], INT32 node_num)
{
	INT32 i = 0;
	INT32 j = 0;
	IDF_TREE_NODE *node_ptr0 = NULL;
	IDF_TREE_NODE *node_ptr1 = NULL;
	IDF_TREE_NODE **tree_node = NULL;
	if(NULL == node_len || node_num <= 0)//参数检查
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n",__func__);
		return R_ERROR;
	}
	if(NULL ==(tree_node = i_calloc(node_num ,sizeof(void *), I_IDF, 0)))//申请空间
	{
		log_message(LOG_ERROR, "%s: No memory.\n", __func__);
		return R_ERROR;
	}
	for(i = 0; i < node_num; i++)
	{
		if(-1 != node_len[i])
		{
			if(NULL == (node_ptr0 = (IDF_TREE_NODE *)i_calloc(sizeof(IDF_TREE_NODE), sizeof(INT8), I_IDF, 0)))
			{
				for(j = 0; j < i ; j++)
					i_free(tree_node[i]);
				i_free(tree_node);
				log_message(LOG_ERROR, "%s: No memory.\n", __func__);
				return R_ERROR;
			}
			node_ptr0->len = node_len[i];
			tree_node[i] = node_ptr0;
			if (i != 0) 
            {
                if (tree_node[(i - 1) / 2] != 0 && (i % 2) == 1)
                {
                    tree_node[(i - 1) / 2]->left_small = node_ptr0;
                }

                else if (tree_node[(i - 1) / 2] != 0 && (i % 2) == 0)
                {
                    tree_node[(i - 1) / 2]->right_big = node_ptr0;
                }
            }
            else  //i=0表示是树根结点
            {
                *tree_root = node_ptr0;
            }
		}
	}
	i_free(tree_node);
	return R_OK;
}
/*====================================================
函数名: init_identifier_map
功能:  初始化树，读取xml文件， 初始化AC
入参:    *idf_tree : 结构体指针， 包括tcp树， udp树， 端口协议
                               映射表
                list: 文件名
出参: 
返回值:  R_OK, R_ERROR
作者:
时间:2013-11
说明: 
======================================================*/
INT32 init_identifier_map(IDF_TREE *idf_tree, INT8 *list)  
{
    INT32 i = 0;
	INT32 j = 0;
    IDF_FILE_LIST  name_list = {0};    /*和结构体namelist重名 */
    FILE  *p = NULL; 
    INT32 tcp_node_plen[16] = {184,68,731,34,96,280,-1,6,60,-1,-1,246,-1,-1,-1,-1};
	INT32 udp_node_plen[16] = {394,44,1079,29,-1,760,-1,22,-1,-1,-1,-1,-1,-1,-1,-1};
	INT8 file_path[IDF_MAX_FILE_NAME_LEN] = {0};
	INT8 log_str[G_LOG_LEN] = {0};
	if(NULL == list)//参数检查
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n",__func__);
		return R_ERROR;
	}
	if(R_OK != init_tree(&(idf_tree->tcp_tree_root), tcp_node_plen, 16))//初始化 tcp规则树
	{
		log_message(LOG_ERROR, "%s: init_tree return R_ERROR.\n", __func__);
		return R_ERROR;
	}
	if(R_OK != init_tree(&(idf_tree->udp_tree_root), udp_node_plen, 16))//初始化 udp规则树
	{
		free_idf_tree(idf_tree->tcp_tree_root, 16);
		log_message(LOG_ERROR, "%s: init_tree return R_ERROR.\n", __func__);
		return R_ERROR;
	}
    
    // 读取文件，得到要识别协议列表和对应的文件路径
    p = fopen(list, "r");
    if (NULL == p) //打开文件失败时， 释放前面的空间
    {
    	free_idf_tree(idf_tree->tcp_tree_root, 16);
		free_idf_tree(idf_tree->udp_tree_root, 16);
    	log_message(LOG_ERROR, "%s: p = fopen(list, \"r\") is NULL.\n", __func__);
		return R_ERROR;
    }
    else 
    {
        fscanf(p, "number:%d\n", &name_list.xml_file_num);// 获取xml的文件数量
        for (i = 0; i < name_list.xml_file_num; i++) //循环读取xml文件
        {
        	if (i >= idf_read_xml_num && idf_read_xml_num != 0)
			{
				break;
			}
            fscanf(p, "%s\n", name_list.file_path[i]);// 获取文件名， 这里没有过滤掉前后空格， 结尾一定需为
												      //'\n’，如果结尾为'\r\n‘,整个处理会出错
			//log_message(LOG_INFO, "file_num:%d, %s\n", i + 1, name_list.file_path[i]);

			if (0 != access(name_list.file_path[i],0) && SET_FLAG != g_license_flag)//文件不存在， 则为加密文件
			{
				 snprintf(file_path,IDF_MAX_FILE_NAME_LEN,"%s.ss",name_list.file_path[i]);  
			} 
			else 
			{	
				snprintf(file_path,IDF_MAX_FILE_NAME_LEN,"%s",name_list.file_path[i]);
			}
            if(R_OK != read_xml(file_path, idf_tree))//读取
            {
            	if (NULL != strstr(name_list.file_path[i],"customer_app")
					|| NULL != strstr(name_list.file_path[i],"customer_rules"))
            	{
            		log_message(LOG_ERROR, "%s: read_xml return R_ERROR.\n", __func__);
					continue;
            	}
            	log_message(LOG_ERROR, "%s: read_xml return R_ERROR.\n", __func__);
				return R_ERROR;
            }
        }
		if(R_OK != init_string_header_list())
		{
			log_message(LOG_ERROR, "%s: init_string_header_list return R_ERROR.\n", __func__);
			return R_ERROR;
		}
		log_message(LOG_INFO, "IDF: the number of xml file:%d.\n",i);
		proc_ac();
    }
    if(p!=NULL) 
		fclose(p);
    return R_OK;
}
/*====================================================
函数名: proc_ac
功能:  根据读取的string，url, char等，处理多模匹配算法树
入参:    
出参: 
返回值:  R_OK, R_ERROR
作者:
时间:2013-11
说明: 
======================================================*/
INT32 proc_ac(void)
{
	INT32 i = 0;
	IDF_AC_STRING *temp = NULL;
	g_acsm = acsmNew();//AC初始化
	temp = g_ac_string;
	while(NULL != temp)
	{
		acsmAddPattern(g_acsm, temp, g_pattern_num);
		g_pattern_num++;
		temp = temp->next;
	}
    acsmCompile (g_acsm);//编译
    return R_OK;
}
/*====================================================
函数名: free_identifier_header_list
功能:  释放协议头链表
入参:    list_header: 头指针
出参: 
返回值:  R_OK, R_ERROR
作者:
时间:2013-11
说明: 
======================================================*/
INT32 free_idf_header_list(IDF_HEADER * list_header)
{
	T_IDF_RULE *cluster = NULL;
	T_IDF_RULE *temp_cluster = NULL;
	IDF_HEADER *node = NULL;
	IDF_HEADER *temp_node = NULL;
	if(NULL == list_header)
		return R_OK;
	node = list_header;
	while(NULL != node)
	{
		cluster = (T_IDF_RULE *)node->idf_rule;
		while(NULL != cluster)// 释放规则头节点中的具体规则的链表
		{
			temp_cluster = cluster;
			cluster = cluster->next;
			i_free(temp_cluster);
		}
		temp_node = node;//  释放规则头链表
		node = node->next;
		i_free(temp_node);
	}
	return R_OK;
}
/*====================================================
函数名: free_idf_tree
功能:  释放协议规则树
入参:    tree_root: 树的根节点
                node_num:节点个数,堆栈的最大值
出参: 
返回值:  R_OK, R_ERROR
作者:
时间:2013-11
说明:  使用递归更方便
======================================================*/
INT32 free_idf_tree(IDF_TREE_NODE*tree_root, INT32 node_num)
{
	IDF_TREE_NODE **stack;
	INT32 i = 0;
	IDF_TREE_NODE *node_ptr = NULL; 
	if(NULL == tree_root || node_num <= 0)
		return R_OK;
	if(NULL == (stack = i_malloc(sizeof(void *) * node_num, I_IDF, 0)))//申请堆栈
	{
		log_message(LOG_ERROR,  "%s: No memory.\n");
		return R_ERROR;
	}
	memset(stack, 0 , sizeof(void *) * node_num);//清0
	stack[0] = tree_root;//在堆栈中放入根节点
	for(i = 0;i < node_num && stack[i] != NULL;)
	{
		node_ptr = stack[i--];//在堆栈中取节点
        if (node_ptr->left_small != NULL)
        {
            stack[++i] = node_ptr->left_small; //入堆栈
        }
        else 
        {
            if (node_ptr->left_header != NULL)
            {
                free_idf_header_list(node_ptr->left_header);//释放左链表
            }
        }
        
        if (node_ptr->right_big != NULL)
        {
            stack[++i] = node_ptr->right_big;//入堆栈
        }
        else 
        {
            if (node_ptr->right_header != NULL)
            {
                free_idf_header_list(node_ptr->right_header);//释放右链表
            }
        }
		i_free(node_ptr);//释放树节点
        if (i < 0)//堆栈为空了， 已经处理完
        {
            break;
        }
	}
	i_free(stack);
	return R_OK;
}
/*====================================================
函数名: free_idf_map
功能:  释放tcp树和udp树
入参:     *idf_tree : 结构体指针， 包括tcp树， udp树， 端口
               协议映射表
出参: 
返回值:  R_OK, R_ERROR
作者:dingdong
时间:2013-11
说明: 
======================================================*/
INT32 free_idf_map(IDF_TREE  *idf_tree)
{
    if(NULL == idf_tree)
		return R_OK;
	if(NULL != idf_tree->tcp_tree_root)
	{
		free_idf_tree(idf_tree->tcp_tree_root, 16); //释放结构体里 的tcp规则树
	}
	if(NULL != idf_tree->udp_tree_root)
	{
		free_idf_tree(idf_tree->udp_tree_root, 16);//释放结构体里的UDP规则树
	}
	i_free(idf_tree);
	return R_OK;
}
/*====================================================
函数名: free_port_ip_tbl
功能:  释放port_ip表的空间
入参:    *input_tbl: port_ip表
出参: 
返回值:  R_OK, R_ERROR
作者:dingdong
时间:2013-11
说明: 
======================================================*/
INT32 free_port_ip_tbl(IDF_PORT_IP_MAP_TBL *input_tbl)
{
	INT32 i = 0;
	if(NULL == input_tbl)
		return R_OK;
	if(NULL != input_tbl->store_address)
		i_free(input_tbl->store_address);
	i_free(input_tbl);
	input_tbl = NULL;
	return R_OK;
}
/*====================================================
函数名: clear_port_ip_tbl
功能:  清空port_ip表的空间
入参:    *input_tbl: port_ip表
出参: 
返回值:  
作者:
时间:
说明: 
======================================================*/
void clear_port_ip_tbl()
{
	INT32 i = 0 , j = 0;
    IDF_IP_PROTO_NODE *pip = NULL, *pip_prev = NULL, *temp_pip = NULL;
    if (NULL == g_port_ip_tbl || NULL == g_port_ip_tbl->free_node) //检查
    {
    	log_message(LOG_ERROR, "%s: g_port_ip_tbl or g_port_ip_tbl->free_node is NULL.\n", __func__);
        return;
    }
    
    pthread_rwlock_wrlock(&g_port_ip_tbl->lock);//全锁住
    for (i = 0; i < IDF_PORT_NUM; i++) //一个一个桶操作
    {
		pip = g_port_ip_tbl->node_index[i];
        pip_prev = NULL;
        while (pip) //循环访问桶下的链表
        {
        	temp_pip = pip;
			pip = pip->next;
			if(NULL == pip_prev)
				g_port_ip_tbl->node_index[i] = pip;
			else
				pip_prev->next = pip;
			temp_pip->next = g_port_ip_tbl->free_node;
			g_port_ip_tbl->free_node = temp_pip;
			(g_port_ip_tbl->free_node_num)++;
       	}
     }
     pthread_rwlock_unlock(&g_port_ip_tbl->lock);//解锁
       
}

/*====================================================
函数名: free_ac_string
功能:  释放ac_string链表空间
入参:    *input_list: 待释放的链表头
出参: 
返回值:  R_OK, R_ERROR
作者:dingdong
时间:2013-11
说明: 
======================================================*/
INT32 free_ac_string(IDF_AC_STRING *input_list)
{
	IDF_AC_SUB *pre_sub_node = NULL;
	IDF_AC_SUB *sub_node = NULL;
	IDF_AC_STRING *pre_node = NULL;
	IDF_AC_STRING *node = NULL;
	if(NULL == input_list)
		return R_OK;
	node = input_list;
	while(NULL != node)
	{
		pre_sub_node = NULL;
		sub_node = node->string_header;
		while(NULL != sub_node)
		{
			pre_sub_node = sub_node;
			sub_node = sub_node->next;
			i_free(pre_sub_node);
		}
		pre_node = node;
		node = node->next;
		i_free(pre_node);
	}
	return R_OK;
}
/*====================================================
函数名: free_ip_hash_tbl
功能:  释放ip hash表的空间
入参:    *input_tbl: 待释放的表
出参: 
返回值:  R_OK, R_ERROR
作者:dingdong
时间:2013-11
说明: 
======================================================*/
INT32 free_ip_hash_tbl(IDF_IP_HASH_TBL *input_tbl)
{
	if(NULL == input_tbl)
		return R_OK;
	if(NULL != input_tbl->store_address)
		i_free(input_tbl->store_address);
	if(NULL != input_tbl->tbl)
		i_free(input_tbl->tbl);
	i_free(input_tbl);
	return R_OK;
}
/*====================================================
函数名: free_idf_resource
功能:  释放所有的资源
入参:    
出参: 
返回值:  R_OK, R_ERROR
作者:dingdong
时间:2013-11
说明: 
======================================================*/
INT32 free_idf_resource(void)
{
	if(NULL != g_string_idf_header)
	{
 		free_idf_header_list(g_string_idf_header);
		g_string_idf_header = NULL;
	}
	if(NULL != g_acsm)
	{
		acsmFree(g_acsm);
		g_acsm = NULL;
	}
	if(NULL != g_idf_tree)
	{
		free_idf_map(g_idf_tree);
		g_idf_tree = NULL;
	}
	//if(NULL != g_port_ip_tbl)
		//free_port_ip_tbl(g_port_ip_tbl);
	if(NULL != g_ac_string)
	{
		free_ac_string(g_ac_string);
		g_ac_string = NULL;
	}
	if(NULL != g_ip_hash_tbl)
	{
		free_ip_hash_tbl(g_ip_hash_tbl);
		g_ip_hash_tbl = NULL;
	}
	memset(&g_string_get, 0, sizeof(IDF_STRING_SPECIAL));
	memset(&g_string_ooo, 0, sizeof(IDF_STRING_SPECIAL));
	memset(&g_string_oo, 0, sizeof(IDF_STRING_SPECIAL));
	memset(&g_bitmap_cmp, 0, IDF_MAX_BITMAP_LEN);
	memset(&g_tcp_bit_map, 0, sizeof(IDF_BIT_MAP));
	memset(&g_udp_bit_map, 0, sizeof(IDF_BIT_MAP));
	memset(&g_port_proto_tbl, 0, sizeof(IDF_PORT_PROTO_TBL));
	g_pattern_num = 0;
	return R_OK;
}
/*====================================================
函数名: init_special_string
功能:  初始化g_ac_string, 在其中插入特殊字符串对应的节点
入参:    
出参: 
返回值:  R_OK, R_ERROR
作者:dingdong
时间:2013-11
说明: 
======================================================*/
INT32 init_special_string(void)
{
	INT8 string_get[] = "GET ";
	INT8 string_ooo[3]={0};
	INT8 string_oo[2] = {0};
	IDF_STRING idf_string_get = {0};
	IDF_STRING idf_string_ooo = {0};
	IDF_STRING idf_string_oo =  {0};
	snprintf(idf_string_get.content, IDF_MAX_STRING_LEN, "GET ");
	idf_string_get.content_len = strlen("GET ");
	idf_string_get.type = STRING;
	idf_string_ooo.content_len = 3;
	idf_string_ooo.type = STRING;
	idf_string_ooo.offset = -1; //
	idf_string_oo.content_len = 2;
	idf_string_oo.type = STRING;
	idf_string_oo.offset = -1;
	if(R_OK != insert_ac_string(&idf_string_get, 0, SET_FLAG, IDF_STRING_GET_POSITION))
		goto _end;
	if(R_OK != insert_ac_string(&idf_string_get, 0, RESET_FLAG, IDF_STRING_GET_POSITION))
		goto _end;
	if(R_OK != insert_ac_string(&idf_string_ooo, 0, SET_FLAG, IDF_STRING_OOO_POSITION))
		goto _end;
	if(R_OK != insert_ac_string(&idf_string_ooo, 0, RESET_FLAG, IDF_STRING_OOO_POSITION))
		goto _end;
	if(R_OK != insert_ac_string(&idf_string_oo, 0, SET_FLAG, IDF_STRING_OO_POSITION))
		goto _end;
	if(R_OK != insert_ac_string(&idf_string_oo, 0, RESET_FLAG, IDF_STRING_OO_POSITION))
		goto _end;
	g_tcp_bit_map.used_num = IDF_MAP_SPECAIL_BITMAP;
	g_udp_bit_map.used_num = IDF_MAP_SPECAIL_BITMAP;
	g_tcp_bit_map.bit_map[IDF_STRING_GET_POSITION] = &g_string_get;
	g_udp_bit_map.bit_map[IDF_STRING_GET_POSITION] = &g_string_get;
	g_tcp_bit_map.bit_map[IDF_STRING_OOO_POSITION] = &g_string_ooo;
	g_udp_bit_map.bit_map[IDF_STRING_OOO_POSITION] = &g_string_ooo;
	g_tcp_bit_map.bit_map[IDF_STRING_OO_POSITION] = &g_string_oo;
	g_udp_bit_map.bit_map[IDF_STRING_OO_POSITION] = &g_string_oo;
	return R_OK;
_end:
	log_message(LOG_ERROR,  "%s: insert_ac_string return R_ERROR.\n", __func__);
	return R_ERROR;
}
/*====================================================
函数名: init_idf
功能:  总初始化函数， 对外接口
入参:     
出参: 
返回值:  R_OK, R_ERROR
作者:dingdong
时间:2013-11
说明:  
======================================================*/
INT32 init_idf(void)  
{
	INT8 time_str[TIME_LENGTH] = {0};
	pthread_t check_thread = {0};
	if (R_OK != decrypt_license_ss()) 
	{
		g_license_flag = SET_FLAG;
	}
	if(SET_FLAG != g_license_flag)//解析license.ss成功， 才执行
	{
		if (R_OK != verify_password_information())
		{
			log_message(R_ERROR,"verify information fail.\n");
			return R_ERROR;
		}
		log_message(LOG_INFO, "IDF: license_release_version:%s.\n",license_release_version);
		log_message(LOG_INFO, "IDF: license_release_date:%s.\n",license_release_date);	
		if(NULL != license_release_date) i_free(license_release_date);
		if(NULL != license_release_version) i_free(license_release_version);
	}
	log_message(LOG_INFO, "IDF: %s", IDF_VERSION);
	get_cfg();// 获取配置信息
	free_idf_resource();//释放所有的数据空间
	if(0 == g_init_count_num)  //第一次初始化时运行
	{
		if(R_OK != init_port_ip_tbl(&g_port_ip_tbl))
		{
			log_message(LOG_ERROR, "%s: init_temp_port_ip return R_ERROR.\n");
			return R_ERROR;
		}
		if(R_OK != init_port_ip_tbl(&g_ftp_port_ip_tbl))
		{
			log_message(LOG_ERROR, "%s: init_temp_port_ip return R_ERROR.\n");
			return R_ERROR;
		}
		if(0 != pthread_create(&check_thread, NULL, port_ip_tbl_scan, NULL))
		{
			log_message(LOG_ERROR,  "%s: fail to create thread to exec do_temp_port_ip_scan.\n");
			return R_ERROR;
		}
		g_init_count_num++;
	}
	if(R_OK != init_ip_hash_tbl(&g_ip_hash_tbl,IDF_IP_HASH_TBL_BUCK_NUM, IDF_IP_HASH_TBL_NODE_NUM))
	{
		log_message(LOG_ERROR, "%s: init_ip_hash_tbl return R_ERROR.\n", __func__);
		return R_ERROR;
	}
	if(R_OK != init_special_string())
	{
		log_message(LOG_ERROR, "%s: init_special_string return R_ERROR.\n", __func__);
		return R_ERROR;
	}
	if(NULL == (g_idf_tree = i_calloc(sizeof(IDF_TREE), 1, I_IDF, 0)))  //申请空间
    {
    	log_message(LOG_ERROR, "%s: No memory.\n", __func__);
		return R_ERROR;
    }
    if(R_OK != init_identifier_map(g_idf_tree, IDF_PROTO_LIST_FILE))//初始化树
    {
    	log_message(LOG_ERROR, "%s: init_identifier_map return R_ERROR.\n", __func__);
		return R_ERROR;
    }
	
	debug_print();
	
	if(NULL != g_fp)
	{
		fclose(g_fp);
		g_fp = NULL;
	}
	if(NULL == (g_fp = fopen(LOG_FILE, "a+")))
	{
		log_message(LOG_ERROR, "%s: fopen %s return NULL.\n", __func__,LOG_FILE);
		return R_ERROR;
	}
	get_str_time(time_str, TIME_LENGTH);
	fprintf(g_fp,"%s %s",time_str,IDF_VERSION);
	LOCK_INIT(&g_print_lock);
	
    return R_OK;
}
/*====================================================
函数名: get_cfg
功能:  从配置文件中获取需要的配置值
入参:    
出参:
返回值:  
作者:
时间:2013-10-25
说明: 
======================================================*/
void get_cfg(void)
{
	INT8 cfg_file_content[G_MAX_CFG_LEN] = {0};
	INT8 switch_item[] = "log_switch";
	INT8 level_item[] = "log_level";
	UINT8 flag = 0;
	INT32 result = 0;
	if(R_OK != get_cfg_file_content(g_cfg_file_name, cfg_file_content, G_MAX_CFG_LEN))
	{// 如果不能打开配置文件或者配置文件有问题， 使用默认值
		//log_message(LOG_ERROR, "%s: get_cfg_file_content return R_ERROR.\n", __func__);
		debug_switch = 0;
		debug_print_level = 1;
		return;
	}
	if(R_OK != get_cfg_int(cfg_file_content, switch_item, &result, &flag))//获取log_switch
	{
		log_message(LOG_ERROR, "%s: get_cfg_int return R_ERROR.\n", __func__);
		return;
	}
	if(R_YES == flag)
	{
		if(0 == result)
			debug_switch = 0;
		else
			debug_switch = 1;
	}
	else
	{
		log_message(LOG_ERROR, "%s: fail to get item:%s from %s.\n", __func__, switch_item, g_cfg_file_name);
	}
	if(R_OK != get_cfg_int(cfg_file_content, level_item, &result, &flag))//获取log_level
	{
		log_message(LOG_ERROR, "%s: get_cfg_int return R_ERROR.\n", __func__);
		return ;
	}
	if(R_YES == flag)
	{
		if(result >= 0 && result <= 3)
			debug_print_level = result;
	}
	else
	{
		log_message(LOG_ERROR, "%s: fail to get item:%s from %s.\n", __func__, level_item, g_cfg_file_name);
	}
	return;
}
/*====================================================
函数名: check_payload_first_byte
功能:   判断给定的负载第一个字节是否为0x24
入参:    *packet_payload: 负载
         *packet_length: 负载长度
                
出参:  无        
返回值:  R_OK, R_ERROR
作者:
时间:2013-11
说明: 
======================================================*/
INT32 check_payload_first_byte(char *packet_payload, int packet_length)
{
	UINT8 first_byte  = 0x24;
	UINT8 fourth_byte  = 0x80;
	if (packet_payload == NULL || packet_length <= 0) 
	{
		return R_ERROR;
	}
	
	if (first_byte == (UINT8)packet_payload[0] && packet_length > 5 && fourth_byte == (UINT8)packet_payload[4])
	{
		return R_OK;
	}
	
	return R_ERROR;	
}

/**********************************************************/
/* 以下条件编译是直接从给定的目录下读取
该目录下所有的xml文件并解析，不需要从
protocol.lst文件中读取xml文件名称 */
/*
#define    IDF_PROTO_LIST_FILE   "./protocol_identifier_xml_file"
#define FILE_PATH_LENGTH 256 
====================================================
函数名: trave_dir
功能:   遍历给定目录下所有的文件，并解析
入参:    *path: 目录名
         *idf_tree: 规则树
                
出参:  无        
返回值:  R_OK, R_ERROR
作者:
时间:2013-11
说明: 
======================================================
int trave_dir(char *path, IDF_TREE *idf_tree)
{
	DIR *dir_ptr;     				// 定义目录类型的指针                
	struct dirent *direntp;       	// 定义用于读目录的缓冲区
	struct stat sb;
	char absolute_path[FILE_PATH_LENGTH];
	char temp_path[FILE_PATH_LENGTH];
	
    if (path == NULL || idf_tree == NULL)
	{
		return R_ERROR;
	}
	// 转换成绝对路径 
	if (realpath(path, absolute_path) == NULL)
	{
		printf("transform fail\n");
		return R_ERROR;
	}
	if ((dir_ptr = opendir(absolute_path)) == NULL) 
	{		
		printf("Can’t open!\n");
		return R_ERROR;
	}
	
    while ((direntp = readdir(dir_ptr)) != NULL) 
	{
        //把当前目录.，上一级目录..及隐藏文件都去掉
        if (strncmp(direntp->d_name, ".", 1) == 0)
            continue;
        snprintf(temp_path, FILE_PATH_LENGTH, "%s/%s", absolute_path, direntp->d_name);
        if (stat(temp_path, &sb) >= 0 && S_ISDIR(sb.st_mode)) 
		{
            trave_dir(temp_path, idf_tree);
        } 
		else 
        {
			if(R_OK != read_xml(temp_path, idf_tree)) 
			{
            	log_message(LOG_ERROR, "%s: read_xml return R_ERROR.\n", __func__);
				return R_ERROR;
            }
		}
    }
    closedir(dir_ptr);
    return R_OK;
}*/
/*====================================================
函数名: decrypt_license_ss
功能:	从licence.ss 中解密
入参:	无				
出参:  无		 
返回值:  R_OK, R_ERROR
作者:
时间:2014-01
说明: 
======================================================*/
INT32 decrypt_license_ss()
{
	INT8 *output = NULL;
	struct AVDES des = {0};
	UINT32 len = 0;
	UINT32 num = 0;
	UINT8 key[] = {0x14, 0x34, 0x56, 0x78, 0x9a, 0xb5, 0xde, 0xf0};
	if(0 != access("license.ss", 0))//判断license.ss是否存在
	{
		g_license_flag = SET_FLAG; //设置全局标识
		return R_ERROR;
	}
	if (NULL == (output = allocate_des_memory("license.ss",&len)))
	{	
		log_message(R_ERROR,"%s:allocate des memory fail.\n");
		return R_ERROR;
	}
	
	num = (0 == len % 8) ? (len/8): (len/8 + 1);
	av_des_init(&des, key, 64, 0);
	av_des_crypt(&des, output, output, num, NULL, 1);
	if (R_ERROR == get_information(output))
	{
		if (output != NULL)
		{
			i_free(output);
		}
		log_message(R_ERROR,"get_information fail.\n");
		return R_ERROR;
	}

	return R_OK;
}
/*====================================================
函数名: allocate_des_memory
功能:	为文件分配内存
入参:	filename 文件名
		len 文件长度
出参:  无		 
返回值:  成功返回地址，失败返回NULL
作者:
时间:2014-01
说明: 
======================================================*/
INT8 *allocate_des_memory(INT8 *filename, INT32 *len)
{
	INT32 fd = -1;
	struct stat buf = {0};
	INT8 *output = NULL;
	
	if (NULL == filename || NULL == len) 
	{
		log_message(R_ERROR,"%s:parameter error.\n",__func__);
		return NULL;
	}
	fd = open(filename, 0);
	if (-1 == fd) 
	{
		log_message(LOG_ERROR,"%s:open %s failed.\n",__func__, filename);
		return NULL;
	}
	if (-1 == fstat(fd, &buf)) 
	{
		log_message(LOG_ERROR, "%s:fail to stat.\n", __func__);
		close(fd);
		return NULL;
	}
	if (NULL == (output = i_calloc((buf.st_size), 1, I_IDF, 0))) 
	{
		log_message(LOG_ERROR,"%s:allocate memory fail.\n",__func__);
		close(fd);
		return NULL;
	}
	if (read(fd, output, buf.st_size) != buf.st_size)
	{
		log_message(LOG_ERROR, "%s:read fail.\n", __func__);
		i_free(output);
		close(fd);
		return NULL;
	}
	*len = buf.st_size;
	close(fd);
	return output;
}
/*====================================================
函数名: verify_password_information
功能:	验证密码信息
入参:	无				
出参:  无		 
返回值:  R_OK, R_ERROR
作者:
时间:2014-01
说明: 
======================================================*/
INT32 verify_password_information()
{
	time_t tm = 0;

	tm = time(NULL);
	if (tm < idf_valid_start_time || tm > idf_valid_end_time) 
	{
		log_message(R_ERROR,"idf time out.\n");
		return R_ERROR;
	}
	return R_OK;
	
}
/*====================================================
函数名: get_license_information
功能:	从字符串中提取内容
入参:	des 目的字符串			
出参:  str_start 要提前的字符串开始
		 str_end 要提取的字符串结束
返回值:  
作者:
时间:2014-01
说明: 
======================================================*/
INT8* get_license_information(INT8 *des, INT8 *str_start, INT8 *str_end)
{
	INT8 temp[256] = {0};
	INT8 *key = NULL;
	
	if(NULL == des || NULL == str_start || NULL == str_end) 
	{
		log_message(R_ERROR,"%s:parameter error.",__func__);
		return NULL;
	}
	if(R_YES == get_middle_str(des, strlen(des), str_start, strlen(str_start), str_end, strlen(str_end), temp, 256))
	{
		key = (INT8*)i_calloc(strlen(temp),1,I_IDF,0);
		if (key == NULL) 
		{
			log_message(R_ERROR, "%s:allocate memory fail.\n",__func__);
			return NULL;
		}
		memcpy(key, temp, strlen(temp));
	}
	return key;
}
/*====================================================
函数名: get_information
功能:	从字符串中提取内容
入参:	des 目的字符串			
出参:  output 字符串
返回值: R_OK,R_ERROR 
作者:
时间:2014-01
说明: 
======================================================*/
INT32 get_information(INT8 *output) 
{
	INT8 *xml_key = NULL;
	INT8 *read_xml_num = NULL; 
	INT8 *valid_start_time = NULL;
	INT8 *valid_end_time = NULL;
	struct tm temp_start_time = {0};
	struct tm temp_end_time = {0};
	UINT64 temp = 0;
	
	if (NULL == output) 
	{
		log_message(R_ERROR,"%s:parameter error.\n",__func__);
		return R_ERROR;
	}
	
	if (NULL == (xml_key = get_license_information(output,"xml_rule_password:",";"))) 
	{
		log_message(LOG_ERROR, "%s:get_license_information fail.\n",__func__);
		return R_ERROR;
	}
	temp = strtoull(xml_key, 0, 10);
	memcpy(xml_rule_key, xml_key, 8);
	i_free(xml_key);
	
	if (NULL == (read_xml_num = get_license_information(output,"idf_read_xml_num:",";")))
	{
		log_message(LOG_ERROR, "%s:get idf_read_xml_num fail.\n",__func__);
		return R_ERROR;
	}
	idf_read_xml_num = atoi(read_xml_num);
	i_free(read_xml_num);
	
	if (NULL == (valid_start_time = get_license_information(output,"idf_valid_start_time:",";")))
	{
		log_message(LOG_ERROR, "%s:get idf_valid_start_time fail.\n",__func__);
		return R_ERROR;
	}
	strptime(valid_start_time, "%Y/%m/%d", &temp_start_time);
	i_free(valid_start_time);
	if (-1 == (idf_valid_start_time = mktime(&temp_start_time))) 
	{
		log_message(R_ERROR,"%s:date format error.\n",__func__);
		return R_ERROR;
	}
	
	if (NULL == (valid_end_time = get_license_information(output,"idf_valid_end_time:",";")))
	{
		log_message(LOG_ERROR, "%s:get idf_valid_end_time fail.\n",__func__);
		return R_ERROR;
	}
	strptime(valid_end_time, "%Y/%m/%d", &temp_end_time);
	i_free(valid_end_time);
	temp_end_time.tm_hour = 23;
	temp_end_time.tm_min = 59;
	temp_end_time.tm_sec = 59;
	if (-1 == (idf_valid_end_time = mktime(&temp_end_time))) 
	{
		log_message(R_ERROR,"%s:date format error.\n",__func__);
		return R_ERROR;
	}

	if (NULL == (license_release_date = get_license_information(output,"license_release_date:",";"))) 
	{
		log_message(LOG_ERROR, "%s:get license_release_date fail.\n",__func__);
		return R_ERROR;
	}

	if (NULL ==(license_release_version = get_license_information(output, "license_release_version:",";")))
	{
		i_free(license_release_date);
		log_message(LOG_ERROR, "%s:get license_release_version fail.\n",__func__);
		return R_ERROR;	
	}
	i_free(output);
	return R_OK;
}

/*====================================================
函数名: decrypt
功能:	从文件中解密
入参:	temp_path 文件路径			
出参:  content 解密后的内容
		 content_len 解密后的内容长度
返回值:  R_OK, R_ERROR
作者:
时间:2014-01
说明: 
======================================================*/
INT32 decrypt(INT8 *temp_path, INT8 **content, INT32 *content_len) 
{
	struct AVDES des = {0};
	INT32 num = 0;

	if (NULL == temp_path || NULL == content || NULL == content_len) 
	{
		log_message(R_ERROR,"%s:parameter error.\n",__func__);
		return R_ERROR;
	}
	if (NULL == (*content = allocate_des_memory(temp_path,content_len)))
	{	
		log_message(R_ERROR,"%s:allocate des memory fail.\n",__func__);
		return R_ERROR;
	}
	
	num = (0 == *content_len % 8) ? (*content_len/8): (*content_len/8 + 1);
	av_des_init(&des, xml_rule_key, 64, 0);
	av_des_crypt(&des, *content, *content, num, NULL, 1);
	return R_OK;
}
/*====================================================
函数名: idf_get_version_str
功能:	返回版本号， 因不是所有地方都需要，
             函数未加入接口idf.h中, 由icare调用
入参:			
出参: 
返回值:  版本号
作者:
时间:2014-03
说明: 
======================================================*/
INT8 *idf_get_version_str(void)
{
	return IDF_VERSION;
}
/*====================================================
函数名: idf_get_version
功能:	返回版本号对应的数字， 因不是所有地方都需要，
             函数未加入接口idf.h中, 由icare调用
入参:			
出参: 
返回值:  版本号
作者:
时间:2014-03
说明:   数字的计算方法， 如3.0.7， 为
3 * 10000 + 0 * 100 + 7 , 为方便， 人为直接填写IDF_VERSION_NUM
======================================================*/
UINT32 idf_get_version(void)
{
	return IDF_VERSION_NUM;
}

