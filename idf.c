#include "idf_struct.h"
#include "idf_acsmx.h"
#include "idf_debug.h"
#include "idf_des.h"
#include "idf_xml.h"
// this version is test rule idf rate
INT8     IDF_VERSION[] = "libidf.so version:3.0.61 .\n";    //�汾��Ϣ
UINT32	 IDF_VERSION_NUM = 30061;						 //���㷽��:3*10000 + 0 * 100 + 10

UINT8        debug_switch = 0;                            //���Կ���
UINT8        debug_print_level = 0;                       //��δʹ�ã� ��־��ӡ����

//----------------------ȫ�ֱ�������---------------------------
IDF_TREE             *g_idf_tree;    //������

IDF_PORT_IP_MAP_TBL  *g_port_ip_tbl;   //�˿ں� IP ��
IDF_PORT_IP_MAP_TBL  *g_ftp_port_ip_tbl; //ftp �˿ں�ip ��
IDF_HEADER           *g_string_idf_header;      //string����ͷ����       
IDF_IP_HASH_TBL      *g_ip_hash_tbl;  //ip����hash��
IDF_AC_STRING        *g_ac_string;     //ac_string����
IDF_PORT_PROTO_TBL   g_port_proto_tbl; //�˿�Э��ӳ���
IDF_BIT_MAP          g_tcp_bit_map;    //tcpλͼӳ��
IDF_BIT_MAP          g_udp_bit_map;    //udpλͼӳ��
UINT8 g_bitmap_cmp[IDF_MAX_BITMAP_LEN] = {0}; //ȫ0�� �����Ƚ�λͼ�е������Ƿ�ȫ��Ϊ0
IDF_STRING_SPECIAL   g_string_get; //������� "GET "�������Ϣ
IDF_STRING_SPECIAL   g_string_ooo;  //�������0x00 00 00�������Ϣ
IDF_STRING_SPECIAL   g_string_oo; //�������0x00 00�������Ϣ

ACSM_STRUCT         *g_acsm;               //ACƥ��ʹ�õ�����
INT32                g_pattern_num = 0;    //����ֵ
INT32                g_init_count_num = 0; //��ʼ���Ĵ���
INT32                g_pid_num = 0;        //����ֵ

FILE    *g_fp;                 //��־�ļ����
T_CS    g_print_lock;          //��־��ӡ��
INT8    g_cfg_file_name[] = "appidf.cfg";     //���õ�����


INT8   g_special_string_get[] = "GET ";   //"GET "�����ַ���
INT8   g_special_string_ooo[3] = {0};     //"0x00 00 00"�����ַ���
INT8   g_special_string_oo[2] = {0};      //"0x00 00"�����ַ���

UINT8 xml_rule_key[8] = {0};   // xml �������� 
UINT32 idf_read_xml_num = 0;  //�����ȡ�Ķ�ȡ��xml����
#define XML_RULE_NUMBER 800	  // xml ������
time_t  idf_valid_start_time = 0;	// �������Ч��ʼʱ��
time_t  idf_valid_end_time = 0;		// �������Ч����ʱ��
INT8 *license_release_date = NULL;
INT8 *license_release_version = NULL;

UINT8  g_license_flag   =  RESET_FLAG;//�Ƿ��ȡlicense_ss�� SET_FLAG��ʾδ��ȡ

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
������: init_ip_hash_tbl
����:   ��ʼ��ip�����hash��
���:   **hash_table: hash��ָ��
              buck_num: hash���Ͱ��
              node_num: hash���еĽڵ���
����:
����ֵ:  R_OK, R_ERROR
����:  dingdong
ʱ��:2013-11
˵��:
======================================================*/
INT32 init_ip_hash_tbl(IDF_IP_HASH_TBL **hash_table, INT32 buck_num, INT32 node_num)
{
	INT32 i = 0;
	if(buck_num <= 0 || node_num <= 0)//�������
	{
		log_message(LOG_ERROR,  "%s:Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	if(NULL == ((*hash_table) = (IDF_IP_HASH_TBL *)i_calloc(sizeof(IDF_IP_HASH_TBL), 1, I_IDF, 0)))//����hash��
	{
		log_message(LOG_ERROR, "%s: No memory.\n", __func__);
		return R_ERROR;
	}
	if(NULL == ((*hash_table)->tbl = i_calloc(sizeof(void *), buck_num, I_IDF, 0)))//����hashͰ
	{
		log_message(LOG_ERROR, "%s: No memory.\n", __func__);
		i_free(*hash_table);
		return R_ERROR;
	}
	if(NULL == ((*hash_table)->free_node = i_calloc(sizeof(IDF_IP_NODE), node_num, I_IDF, 0)))//����hash�ڵ�
	{
		log_message(LOG_ERROR,  "%s: No memory.\n", __func__);
		i_free(*((*hash_table)->tbl));
		i_free((*hash_table));
		return R_ERROR;
	}
	(*hash_table)->store_address = (*hash_table)->free_node;//free�ռ�ʱʹ��
	(*hash_table)->free_node_num = node_num; //���нڵ㸳ֵ
	(*hash_table)->buck_num = buck_num;   //����Ͱ��
	for(i = 0; i < node_num - 1; i++)   //ѭ�������нڵ㴮������ ���һ���ڵ��nextָ����Ϊ��
	{
		(*hash_table)->free_node[i].next = &((*hash_table)->free_node[i + 1]);
	}
	return R_OK;
}
/*====================================================
������: insert_ip_hash_node
����:   ��ip hash���в���ڵ�
���:  insert_node: ������Ľڵ�
             *ip_hash_tbl: ip hash��ָ��
����:
����ֵ:  R_OK, R_ERROR
����: dingdong
ʱ��:2013-11
˵��:
======================================================*/
INT32 insert_ip_hash_node(IDF_IP_NODE insert_node, IDF_IP_HASH_TBL *ip_hash_tbl, UINT16 port_start, UINT16 port_end)
{
	IDF_IP_NODE *temp = NULL;
	IDF_IP_NODE *ip_node = NULL;
	IDF_IP_NODE *pre_node = NULL;
	INT32 hash_value = -1;
	if(NULL == ip_hash_tbl)// �������
	{
		log_message(LOG_ERROR,  "%s: Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	if(0 == ip_hash_tbl->free_node_num)//�ڵ�����
	{
		log_message(LOG_ERROR,  "%s: There is no free node in ip_hash table.\n", __func__);
		return R_OK;
	}
	hash_value = insert_node.ip % ip_hash_tbl->buck_num;  //����hashֵ
	ip_node = ip_hash_tbl->tbl[hash_value];
	while(1)
	{
		if(NULL != ip_node)
		{
			if(ip_node->ip == insert_node.ip && ip_node->is_tcp == insert_node.is_tcp)//ip�Ѿ����ڣ�����������ӡ��־ 
			{
				//log_message(LOG_ERROR,  "%s: The node has been existed,ip:%u, is_tcp:%d.\n", __func__, ip_node->ip, ip_node->is_tcp);
				
				return R_OK;
			}
			else//ָ����һ�ڵ�
			{
				pre_node = ip_node;
				ip_node = ip_node->next;
			}
		}
		else// ip_nodeΪ��
		{
			temp = ip_hash_tbl->free_node; //�ӿ��нڵ���ȡ�ڵ�
			ip_hash_tbl->free_node = ip_hash_tbl->free_node->next;  
			(ip_hash_tbl->free_node_num)--;  //����ֵ��1
			memcpy(temp, &insert_node, sizeof(IDF_IP_NODE));  //���ƽڵ�ֵ
			temp->next = NULL;                                //ָ���ÿ�
			if(NULL == pre_node)   //ǰ�ڵ�Ϊ��
				ip_hash_tbl->tbl[hash_value] = temp;  //ֱ����Ͱ�����  
			else
				pre_node->next = temp;                //��ӽڵ�

			temp->port_start = port_start;
			temp->port_end = port_end;
			return R_OK;
		}
	}
	
}
/*====================================================
������: insert_bitmap_map_tbl
����:   ��λͼӳ�������Ӽ�¼
���:   *idf_rule:  ����ָ��
               is_tcp:  �����Ƿ�Ϊtcp����, SET_FLAGΪ�ǣ� RESET_FLAG Ϊ��
����:  *bit_position:  ���������ӳ����е�λ�ã� ����λͼ��
              ��λ��
����ֵ:  R_OK, R_ERROR
����: dingdong
ʱ��:2013-11
˵��:
======================================================*/
INT32 insert_bitmap_map_tbl(void *idf_rule, UINT8 is_tcp, UINT32 *bit_position)
{
	IDF_BIT_MAP *temp_map = NULL;
	if(NULL == idf_rule || NULL == bit_position)//�������
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	if(SET_FLAG == is_tcp)//  ѡ��ӳ���
		temp_map = &g_tcp_bit_map;
	else
		temp_map = &g_udp_bit_map;
	if(temp_map->used_num < IDF_MAP_SPECAIL_BITMAP)   //�ж�ӳ����еļ�¼ֵ�Ƿ���ڱ���ֵ
	{
		log_message(LOG_ERROR, "%s: The bitmap table do not init, used_num: %d.\n", __func__, temp_map->used_num);
		return R_ERROR;
	}
	if (temp_map->used_num >= IDF_BITMAP_NUM)
	{	
		log_message(LOG_ERROR, "%s:the bitamp table used out",__func__);
		return R_ERROR;
	}
	temp_map->bit_map[temp_map->used_num] = idf_rule; //����ָ��
	*bit_position = temp_map->used_num;  //����λ��ֵ
	(temp_map->used_num)++; //λ��ֵ��1
	return R_OK;
}
/*====================================================
������: insert_ac_sub_list
����:   ��ac_sub_list �����в���ڵ�
���:   *ac_string: ac_sub_list����Χ�ṹ��
               proto_id: Э���
               is_tcp: �����Ƿ�Ϊtcp����, SET_FLAGΪ�ǣ� RESET_FLAG Ϊ��
               bit_position: ��λͼ�е�λ��
               type: ����ΪURL ����STRING
               offset: STRING�����е�ƫ����
����:  
����ֵ:  R_OK, R_ERROR
����:dingdong
ʱ��:2013-11
˵��:
======================================================*/
INT32 insert_ac_sub_list(IDF_AC_STRING *ac_string, UINT32 proto_id, UINT8 is_tcp, UINT32 bit_position, IDF_TYPE type, INT16 offset)
{
	IDF_AC_SUB *ac_sub = NULL;
	if(NULL == ac_string)// �������
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	if(NULL == (ac_sub = (IDF_AC_SUB *)i_calloc(sizeof(IDF_AC_SUB), 1, I_IDF, 0)))//����ڵ�ռ�
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
������: insert_ac_string
����:   ��ac_string�����в���ڵ�
���:   *string:  �ַ���
               string_len: �ַ����ĳ���
               proto_id: Э���
               is_tcp: �Ƿ�Ϊtcp����, SET_FLAGΪ�ǣ� RESET_FLAG Ϊ��
               bit_position:  ��λͼ�е�λ��
����:  
����ֵ:  R_OK, R_ERROR
����:dingdong
ʱ��:2013-11
˵��:
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
	if(NULL == idf_rule || bit_position < 0 || bit_position >= IDF_BITMAP_NUM) //�������
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
		if(temp_ac->content_length != string_len)//�ַ����Ȳ�ƥ�䣬 ����ѭ��
		{
			pre_temp_ac = temp_ac;
			temp_ac = temp_ac->next;
			continue;
		}
		else if(0 == memcmp(temp_ac->content, string, temp_ac->content_length))//���ݱȶ�
		{
			if(R_OK != insert_ac_sub_list(temp_ac, proto_id, is_tcp, bit_position, temp_type, offset))//������ͬʱ����ڵ�
			{
				log_message(LOG_ERROR, "%s: insert_ac_sub_list return R_ERROR.\n", __func__);
				return R_ERROR;
			}
			break;
		}
		else//���ݲ�ƥ�䣬 ����ѭ��
		{
			pre_temp_ac = temp_ac;
			temp_ac = temp_ac->next;
		}
	}
	if(NULL == temp_ac)//û�����������ҵ���Ӧ���ַ���
	{
		if(NULL == (temp_ac = (IDF_AC_STRING *)i_calloc(sizeof(IDF_AC_STRING), 1, I_IDF, 0)))//����IDF_AC_STRING�ṹ�ռ�
		{
			log_message(LOG_ERROR, "%s: No memory.\n", __func__);
			return R_ERROR;
		}
		memcpy(temp_ac->content, string, string_len); //string��ֵ
		temp_ac->content_length = string_len;//���ȸ�ֵ
		temp_ac->pid = ++g_pid_num;
		if(R_OK != insert_ac_sub_list(temp_ac, proto_id, is_tcp, bit_position, temp_type, offset))//����ac_sub_list����
		{
			log_message(LOG_ERROR, "%s: insert_ac_sub_list return R_ERROR.\n", __func__);
			return R_ERROR;
		}
		if(NULL == pre_temp_ac)  //����ac_string����
			g_ac_string = temp_ac;
		else
			pre_temp_ac->next = temp_ac;
	}
	return R_OK;
}

/*====================================================
������: init_string_header_list
����:   ����g_string_idf_header �����ʼ��ӳ����ac�ַ���
���:  
����:  
����ֵ:  R_OK, R_ERROR
����:dingdong
ʱ��:2013-12
˵��:
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
				{//����Ϊ1���ַ����������ַ����� �����д���
					idf_rule = idf_rule->next;
					continue;
				}
				else
				{
					rule = (void *)idf_rule;
				}
			}
			else//��string��url, http_ref����
			{
				idf_rule = idf_rule->next;
				continue;
			}
			if(R_OK != insert_bitmap_map_tbl((void *)rule,idf_header->is_tcp, &bit_position))//��ӳ�������Ӽ�¼
			{
				if(SET_FLAG == idf_header->is_tcp)//  ѡ��ӳ���
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
			if(R_OK != insert_ac_string((void *)rule, idf_header->proto_id, idf_header->is_tcp, bit_position))//��AC_string����Ӽ�¼
			{
				log_message(LOG_ERROR,	"%s: insert_ac_string return R_ERROR.\n", __func__);
				return R_ERROR;
			}
			add_new_bit_record(idf_header, bit_position);//��idf_header�е� bit_position��������Ӽ�¼
			idf_rule = idf_rule->next;
		}
		idf_header = idf_header->next;
	}
	return R_OK;
}
/*====================================================
������: get_ip_hash_proto_id
����:   ��ip hash���л�ȡЭ���
���:   *idf_info: ����Ϣ�ṹ��
              *ip_hash_tbl: ip hash��
����:   *flag: R_NO��ʾ�ҵ�Э��ţ�����Ҫ����������
               R_YES��ʾ��Ҫ������
����ֵ:  R_OK, R_ERROR
����:dingdong
ʱ��:2013-11
˵��:
======================================================*/
INT32 get_ip_hash_proto_id(IDF_INFO *idf_info, IDF_IP_HASH_TBL *ip_hash_tbl, UINT8 *flag, UINT8 is_des)
{
	INT32 hash_value = -1;
	IDF_IP_NODE *ip_node = NULL;
	UINT8 is_tcp = 0;
	if(NULL == idf_info || NULL == ip_hash_tbl ||(is_des != SET_FLAG && is_des != RESET_FLAG))//�������
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	*flag = R_NO; //����Ĭ��ֵ
    if (SET_FLAG == is_des)
    { 
        if(IDF_IPV4 != idf_info->dip.ip_type) //��ֻ֧��ipv4
    	{
	    	*flag = R_YES;
	    	return R_OK;
	    }
	    is_tcp = (IPPROTO_TCP == idf_info->l4_type) ? SET_FLAG : RESET_FLAG;//�����Ƿ�Ϊtcp����is_tcp
	    hash_value = idf_info->dip.ip4_addr.s_addr % ip_hash_tbl->buck_num;//����hashֵ
	    ip_node = ip_hash_tbl->tbl[hash_value];
    }
    else 
    {
        if(IDF_IPV4 != idf_info->sip.ip_type) //��ֻ֧��ipv4
    	{
	    	*flag = R_YES;
	    	return R_OK;
	    }
	    is_tcp = (IPPROTO_TCP == idf_info->l4_type) ? SET_FLAG : RESET_FLAG;//�����Ƿ�Ϊtcp����is_tcp
	    hash_value = idf_info->sip.ip4_addr.s_addr % ip_hash_tbl->buck_num;//����hashֵ
	    ip_node = ip_hash_tbl->tbl[hash_value];
    }
    while(NULL != ip_node)
	{
		if(ip_node->is_tcp == is_tcp)  //tcp��udpƥ��
		{
			if(ip_node->ip == idf_info->sip.ip4_addr.s_addr)//sipƥ��
			{
				if(0 == ip_node->port_start && 0 == ip_node->port_end)//�ж��Ƿ�ʹ�ö˿�
				{
					idf_info->proto_id = ip_node->proto_id;
#ifdef RULE_RATE_TEST
					bit_set_value(&idf_info->rule_use, IPV4_RATE);
#endif
					return R_OK;
				}
				else
				{
					if(idf_info->sport >= ip_node->port_start && idf_info->sport <= ip_node->port_end)//�˿�ƥ��
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
			else if(ip_node->ip == idf_info->dip.ip4_addr.s_addr) //dipƥ��
			{
				if(0 == ip_node->port_start && 0 == ip_node->port_end)//�ж��Ƿ�ʹ�ö˿�
				{
					idf_info->proto_id = ip_node->proto_id;
#ifdef RULE_RATE_TEST
					bit_set_value(&idf_info->rule_use, IPV4_RATE);
#endif

					return R_OK;
				}
				else
				{
					if(idf_info->dport >= ip_node->port_start && idf_info->dport <= ip_node->port_end)//�˿�ƥ��
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
		ip_node = ip_node->next; //ָ����һ�ڵ�
	}
	*flag = R_YES;
	return R_OK;
}
/*====================================================
������: get_PASV_ftp_port
����:   ��FTP�����л�ȡ�˿�
���:    *payload: ��������
                payload_len: ���س���
����:   *output_port: ��ȡ�Ķ˿ںţ� ���ȡʧ�ܣ���дĬ��
               �˿�20
����ֵ:  R_OK, R_ERROR
����: dingdong
ʱ��:2013-10-24
˵��:
  ���ݵ�ԭʼ���ĸ�ʽΪ:
  227 Entering Passive Mode (222,240,210,154,229,193).
  ��ȡ�Ķ˿ں�ʹ�������ڵĺ�����λ�� ��229��193
  �����������ֻ�ȡ�Ķ˿ںŵļ��㷽��Ϊ229 * 256 + 193
    = 58817,  ��229Ϊ���ֽڶ˿ڵĸ��ֽڣ� 193Ϊ���ֽ�

   229 Entering Extended Passive Mode (|||51374|)

   sscanf�������룬 ���޸�
======================================================*/
INT32 get_PASV_ftp_port(const char *payload, UINT16 payload_len, UINT16 *output_port)
{
	INT8 cmp_str[] = "227";
	INT8 temp_str[] = "229";
	INT32 data[6] = {0};
	INT8 load[PASV_FTP_MAX_LEN] = {0};
	if(NULL == payload || NULL == output_port || payload_len < 0)//�������
	{
		log_message(LOG_ERROR, "%s:Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	*output_port = 20;//Ĭ�϶˿�
	if(payload_len < PASV_FTP_MIN_LEN || payload_len >= PASV_FTP_MAX_LEN)//���ȼ��
		return R_OK;
	if(0 == memcmp(payload, cmp_str, strlen(cmp_str)))//�Ƿ���227Ϊ���صĿ�ʼ
	{
		memcpy(load, payload, payload_len);//��֤�ַ��������һλΪ'\0'
		sscanf(load, "%*[^(](%d,%d,%d,%d,%d,%d)%*[^)]", &data[0], &data[1], &data[2], &data[3], &data[4], &data[5]);//��ȡ
		if((0 == data[4] && 0 == data[5]) || data[4] >= 256 || data[5] >= 256)// ��Ч�Լ��
			return R_OK;
		*output_port = (data[4] << 8) + data[5];//������
		return R_OK;
	}
	if(0 == memcmp(payload, temp_str, strlen(temp_str)))//������229Ϊ���صĿ�ʼ
	{
		memcpy(load, payload, payload_len);//��֤�ַ��������һλΪ'\0'
		sscanf(load, "%*[^(](|||%d|)%*[^)]", &data[0]);
		if(0 == data[0])
			return R_OK;
		*output_port = data[0];
	}
	return R_OK;
}
/*====================================================
������: check_idf_bit_position
����:   ������ͷ�µ�ʹ����ac�Ĺ����Ƿ�ƥ��
���:   *idf_header: ����ͷ�ڵ�
               *idf_info: �������
����:  *flag :            ����Ҫ���� R_NO
                                   ��Ҫ����      R_YES
����ֵ:  R_OK, R_ERROR
����:dingdong
ʱ��:2013-11
˵��: 
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
	for(i = 0; i < idf_header->bit_used_num; i++)//������ͷ�м�¼��ÿһ��ʹ����AC�Ĺ����Ƿ���ƥ��
	{
		if(idf_header->bit_position[i] < IDF_MAP_SPECAIL_BITMAP)//Ϊ�����ַ�ʱ������ѭ��
			continue;
		else
		{
			if(R_YES != bit_check_position(idf_info->bitmap, IDF_BITMAP_NUM, idf_header->bit_position[i]))
			{
				*flag = R_NO;//���߹���
				continue;//��ʹ����Ҫ�߹����ˣ� ����Ҫ�������bit_position�����
			}
		}
				
	}
	return R_OK;
}
/*====================================================
������: proc_ac_match
����:   ����ACƥ����λͼ
���:   *idf_info: �������
����:   *flag :            ����Ҫ�������� R_NO
                                   ��Ҫ��������      R_YES
����ֵ:  R_OK, R_ERROR
����:dingdong
ʱ��:2013-11
˵��: 
======================================================*/
INT32 proc_ac_match(IDF_INFO *idf_info, UINT8 *flag)
{
	UINT32 bit_position = 0;
	if(NULL == idf_info || NULL == flag )
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	if(R_YES == bit_is_all_zero(idf_info->bitmap, g_bitmap_cmp, IDF_MAX_BITMAP_LEN))//���λͼ�Ƿ�Ϊȫ0
	{
		*flag = R_YES; //��Ҫ�����߹�����
		return R_OK;
	}
	while(1)
	{
		if(R_OK == bit_get_one_position(idf_info->bitmap, IDF_MAX_BITMAP_LEN, &bit_position))// ��λͼ�л�ȡһλ
		{
			if(bit_position < IDF_MAP_SPECAIL_BITMAP)//��ȡ��λ�ڱ������ڣ� Ϊ�����ַ�������
			{	
				if (IDF_STRING_GET_POSITION != bit_position)
				{
					proc_special_string(bit_position, idf_info, flag);
				}
				bit_reset_position(idf_info->bitmap, IDF_MAX_BITMAP_LEN, bit_position);
			}
			else
				proc_string(bit_position, idf_info, flag); //��ͨ�ַ�������
		}
		else//λͼȫ��Ϊ0��
			break;
		if(R_NO == *flag)//��ʶ��
			break;
	}
	return R_OK;
}
/*====================================================
������: proc_special_string
����:   ���������ַ���
���:  bit_position:  λͼ�е�λ��ֵ
             *idf_info:  �������
����:   *flag :            ����Ҫ�������� R_NO
                                   ��Ҫ��������      R_YES
����ֵ:  R_OK, R_ERROR
����:dingdong
ʱ��:2013-11
˵��: 
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
	if(IPPROTO_TCP  == idf_info->l4_type)//��ȡbit_position��Ӧ��ָ��
		temp_string_special = (IDF_STRING_SPECIAL *)g_tcp_bit_map.bit_map[bit_position];
	else
		temp_string_special = (IDF_STRING_SPECIAL *)g_udp_bit_map.bit_map[bit_position];
	if(NULL == temp_string_special)
	{
		log_message(LOG_ERROR, "%s: ERROR. gdb me.\n", __func__);
		return R_ERROR;
	}
	for(i = 0 ; i < temp_string_special->used_num; i++)//���ʶ�Ӧ�Ĺ���ͷ
	{
		idf_string = (IDF_STRING *)(temp_string_special->string_special[i]);
		idf_header = idf_string->idf_header;
		if(idf_header->is_tcp != (idf_info->l4_type == IPPROTO_TCP ? SET_FLAG : RESET_FLAG))
		{
			continue;
		}
		proc_idf_header(idf_header, idf_info, flag);
		if(R_NO == *flag)//δʶ�� ��ʶ���Ϊ����Э��
			break;
	}
	return R_OK;
}
/*====================================================
������: proc_string
����:   �����ַ�������(����url)
���:  bit_position:  λͼ�е�λ��ֵ
             *idf_info:  �������
����:   *flag :            ����Ҫ�������� R_NO
                                   ��Ҫ��������      R_YES
����ֵ:  R_OK, R_ERROR
����:dingdong
ʱ��:2013-11
˵��: 
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
		
	if(bit_position < IDF_MAP_SPECAIL_BITMAP || bit_position >= IDF_BITMAP_NUM || NULL == idf_info || NULL == flag)//�������
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	*flag = R_YES; //Ĭ������£���Ҫ��������
	if(IPPROTO_TCP == idf_info->l4_type)//����bit_position ��ȡ����Ĺ���
		idf_rule = (T_IDF_RULE *)g_tcp_bit_map.bit_map[bit_position];
	else
		idf_rule = (T_IDF_RULE *)g_udp_bit_map.bit_map[bit_position];
	if(STRING == idf_rule->type)//string����
	{
		idf_string = (IDF_STRING *)idf_rule;
		idf_header = idf_string->idf_header;
	}
	else if(URL == idf_rule->type)//url����
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
������: proc_idf_header
����:   �ӹ���ͷ����
���:  bit_position:  λͼ�е�λ��ֵ
             *idf_info:  �������
����:   *flag :            ����Ҫ�������� R_NO
                                   ��Ҫ��������      R_YES
����ֵ:  R_OK, R_ERROR
����:dingdong
ʱ��:2013-11
˵��: 
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
	if(R_YES == temp_flag)//��Ҫ�ع�����
	{
		if(R_OK != proc_idf_rule(idf_header->idf_rule, idf_info, idf_header->proto_id, &temp_flag))
		{
			log_message(LOG_ERROR, "%s: proc_idf_rule return R_ERROR.\n", __func__);
			return R_ERROR;
		}
		if(R_YES == temp_flag)//ƥ��ɹ�
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
������: proc_idf
����:   �ӹ����ȡЭ���
���:  *idf_info:  �������
              *tree_root: �������ĸ��ڵ�
����:   
����ֵ:  R_OK, R_ERROR
����:dingdong
ʱ��:2013-11
˵��: 
======================================================*/
INT32 proc_idf(IDF_INFO *idf_info,IDF_TREE_NODE *tree_root)
{
	UINT8 flag = 0;
	if(NULL == idf_info || NULL == tree_root)//�������
	{	
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n", __func__);
		return R_ERROR;
	}
	memset(idf_info->bitmap, 0, IDF_MAX_BITMAP_LEN);//��ȫ����0�� �Է�ֹǰ��Ľ���Ժ���Ĳ�����Ӱ��
    if(idf_info->l5_len > 0 && idf_info->l5 != NULL && g_acsm != NULL) //�����ж� 
    {     
        acsmSearch (g_acsm, idf_info->l5, idf_info->l5_len, MatchFound, idf_info); //��ģƥ��
    }
	//��ģƥ��� ���Ƚ��ж�ģƥ��������
	if(R_OK != proc_ac_match(idf_info, &flag))
	{
		log_message(LOG_ERROR,  "%s: proc_ac_match return R_ERROR.\n", __func__);
		return R_ERROR;
	}
	if(R_YES == flag)//��Ҫ�ٴ���
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
������: proc_idf_tree
����:   �ӹ������л�ȡ���
���:  *idf_info:  �������
              *tree_root: �������ĸ��ڵ�
����:   
����ֵ:  R_OK, R_ERROR
����:dingdong
ʱ��:2013-11
˵��: 
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
	if(R_OK != get_idf_header(tree_root, &idf_header, idf_info->l5_len))// ��ȡ����ͷ
	{
		log_message(LOG_ERROR, "%s: get_idf_header return R_ERROR.\n", __func__);
		return R_ERROR;
	}
	while(NULL != idf_header)//��ȡ�ɹ�
	{
		if(R_OK != proc_idf_header(idf_header, idf_info, &flag))//����
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
������: init_port_ip_tbl
����:   ��ʼ��PORT ��IP��Ӧ��
���:   
����:
����ֵ:  R_OK, R_ERROR
����:
ʱ��:2013-11
˵��:
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
    }//�����ڴ�
    pthread_rwlock_init(&temp->lock, NULL);//��ʼ����
    if(NULL == (temp->free_node = i_calloc(sizeof(IDF_IP_PROTO_NODE) , IDF_PORT_IP_MAX_NUM, I_IDF, 0)))
    {
    	log_message(LOG_ERROR, "%s: No memory.\n", __func__);
		i_free(port_ip_tbl);//�ͷ�ǰ��������ڴ�
		return R_ERROR;
    }//�����ڴ�
    temp->store_address = temp->free_node;  //�����ͷ��ڴ�
    temp->free_node_num = IDF_PORT_IP_MAX_NUM;
    for (i = 0; i < (IDF_PORT_IP_MAX_NUM - 1); i++) //�����鴮������
    {
        temp->free_node[i].next = &(temp->free_node[i + 1]);
    }

	*port_ip_tbl = temp;
    return R_OK;
}


/*====================================================
������: get_port_ip_proto_id
����:   �ж�source��dest ip�Ƿ���PORT��IP��Ӧ����
���:    *idf_info : ��������ݵĽṹ��
                type: �����IP���ͣ� ȡֵΪIDF_TYPE_SOURCE ��
                       IDF_TYPE_DEST
����:  *flag: R_NO��ʾ�ҵ�Э��ţ�����������
                R_YES��ʾδ�ҵ�, ��������
����ֵ:  R_OK, R_ERROR
����:
ʱ��:2013-11
˵��:
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
	
	if(IDF_TYPE_SOURCE == type)//����typeֵ��ȡ��Ӧ��port ��ip
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
    pthread_rwlock_rdlock(&port_ip_tbl->lock);//��ס
    node = port_ip_tbl->node_index[port];//�ڶ�Ӧ��Ͱ�в���
    while (NULL != node) //�������в���
    { 
        if ((node->ip.ip_type == ip.ip_type) && 0 == memcmp(&node->ip.addr, &ip.addr, node->ip.ip_type == IDF_IPV4 ? 4 : 16))//�Ƿ���� 
        {
        	idf_info->proto_id = node->proto_id;
			*flag = R_NO;
			gettimeofday(&(node->time), 0);
            break;
        }   
        node = node->next;
    }

    pthread_rwlock_unlock(&port_ip_tbl->lock);//����
	
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
������: do_port_ip_tbl_scan
����:  ʵ�� ִ��port ip ɨ��
���:   IDF_PORT_IP_MAP_TBL *port_ip_tbl 
����:  
����ֵ:  
����:
ʱ��:2014-10
˵��: ����ΰ����Ľṹ����в���
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
    pthread_rwlock_wrlock(&port_ip_tbl->lock);//ȫ��ס
    for (i = 0; i < IDF_PORT_NUM; i++) //һ��һ��Ͱ����
    {
    	pip = port_ip_tbl->node_index[i];
        pip_prev = NULL;
        while (pip) //ѭ������Ͱ�µ�����
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
     pthread_rwlock_unlock(&port_ip_tbl->lock);//����
}
/*====================================================
������: port_ip_tbl_scan
����:   ɨ��PORT ��IP��Ӧ��
���:   
����:
����ֵ:   R_OK, R_ERROR
����:
ʱ��:  2013-11
˵��: �����������̼߳��
======================================================*/
void *port_ip_tbl_scan(void *_arg)
{
    if (NULL == g_port_ip_tbl || NULL == g_port_ip_tbl->free_node
		|| NULL == g_ftp_port_ip_tbl || NULL == g_ftp_port_ip_tbl->free_node) //���
    {
    	log_message(LOG_ERROR, "%s: g_port_ip_tbl or g_port_ip_tbl->free_node is NULL.\n", __func__);
        return NULL;
    }

    while (1) //�߳���ѭ����ʱ���
    {
    	do_port_ip_tbl_scan(g_port_ip_tbl);
		do_port_ip_tbl_scan(g_ftp_port_ip_tbl);
        sleep(60);  //��ʱ���
    }
    return NULL;
}
/*====================================================
������: get_idf_header
����:   �ڹ������и��ݳ���ֵ�ҵ���Ӧ�Ĺ���ͷ����
���:   *tree_root: �������ĸ��ڵ�
               len: ���ĵĳ���ֵ
����:  **output_header:  ����ͷ�����ͷָ��
����ֵ:  R_OK, R_ERROR
����:
ʱ��:2013-11
˵��: 
======================================================*/
INT32 get_idf_header(IDF_TREE_NODE *tree_root, IDF_HEADER **output_header, INT32 len)
{
	IDF_TREE_NODE  *node = NULL;
	IDF_TREE_NODE  *pre_node = NULL;
	if(NULL == tree_root || NULL == output_header || 0 > len)// �������
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n",__func__);
		return R_ERROR;
	}
	node = tree_root;
	pre_node = tree_root;
	while(NULL != node)//�������ҵ���Ӧ��Ҷ�ӽڵ�
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
	if(len <= pre_node->len)//�ڽڵ����ж�ʹ����������������
		*output_header = pre_node->left_header;
	else
		*output_header = pre_node->right_header;
	return R_OK;
}

/*====================================================
������: check_idf_header
����:   ������ͷ�ڵ��Ƿ���Ҫ����������
���:   *header: ����ͷ�ڵ�
               *idf_info: �������
����:   *flag :            ����Ҫ���� R_NO
                                   ��Ҫ����      R_YES
����ֵ:  R_OK, R_ERROR
����:
ʱ��:2013-11
˵��: 
======================================================*/
inline INT32 check_idf_header(IDF_HEADER *header, IDF_INFO *idf_info, UINT8 *flag)
{
	INT32 len = 0;
	if(NULL == header || NULL == idf_info || NULL == flag)//�������
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n",__func__);
		return R_ERROR;
	}
	*flag = R_NO;
	len = idf_info->l5_len;
	if(0 !=  header->bit_used_num)//���ֻ��һ�������߹��� �������1� ���ж���Ӧ�����й���ƥ����
	{
		if(R_OK != check_idf_bit_position(header, idf_info, flag))//�ڼ��ʱ�� ����Ӧ��λ��ҪֵΪ0
		{
			log_message(LOG_ERROR, "%s: check_idf_bit_position return R_ERROR.\n");
			return R_ERROR;
		}
		if(R_YES != *flag)
		return R_OK;
	}
	*flag = R_NO;
	if(0 != header->payload_len)//��������� ��payloadlength��Ч
	{
		if(header->payload_len < 0)
		{
			if((len + header->payload_len) < 0)// ���ĳ��������|payloadlength| �Ŵ���
				return R_OK;
		}
		else if( len != header->payload_len)//��������ȲŴ���
			return R_OK;
	}
	if(len < header->min_len)//payloadlength��Чʱ�� ���ĳ���С�ڹ����е���Сֵ�� ������
		return R_OK;

     //---------------------------�����ӵ��ж�----------------------------------------
	if(0 != CHECK_BIT(idf_info->state, IDF_STATE_POSSIBLE))//��ʶ��Ϊ����ֵ
	{
		if(SET_FLAG == header->is_pos)//ֻ��鿴����Ϊ����ֵ������� �����п���ֵʱ�� �����ȼ�һ��Ҫ��
		{
			if(!(0 != CHECK_BIT(idf_info->state, IDF_IS_PORT) && 1 == idf_info->store_priority && 1 == header->priority))
			{
				if(header->priority <= idf_info->store_priority)//�����ȼ��ȱ���ĵ�
				return R_OK;
			}
		}
	}
	else//��û��ʶ�����ʶ����ȷ����Э��ţ� �����ȼ�������1
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
		if(SET_FLAG == header->is_final_statu && 0 != CHECK_BIT(idf_info->state, IDF_STATE_CURRENT_STATUS))//����һ������ƥ����������
			return R_OK;
		if(0 != strcmp(idf_info->status, header->pre_statu))
			return R_OK;	
	}
	//----------------------------------------------------------------------------------------
	//�ж������еĹ���ͷ���ǵ�������������еĹ���ͷ
	*flag = R_YES;//����
	return R_OK;
}
/*====================================================
������: proc_state_comm
����:   ƥ����״̬����, ������ͨ����(��״̬��) 
���:    *header: ����ڵ㣬 ��ӦXML��type�ֶ�֮������ݣ�
                           ���й�������
                *idf_info: ��������ݵĽṹ��
����:  *flag:  ��ʾ�Ƿ��ع���ڵ������������
                        ��������  R_YES
                        ����������   R_NO        
����ֵ:  ��
����: dingdong
ʱ��:2014-4-12
˵��:  
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
������: proc_state_status_comm
����:   ƥ����״̬����, ����״̬���з�����״̬
               ����
���:    *header: ����ڵ㣬 ��ӦXML��type�ֶ�֮������ݣ�
                           ���й�������
                *idf_info: ��������ݵĽṹ��
����:  *flag:  ��ʾ�Ƿ��ع���ڵ������������
                        ��������  R_YES
                        ����������   R_NO        
����ֵ:  ��
����: dingdong
ʱ��:2014-4-12
˵��:  
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
������: proc_state_status_final
����:   ƥ����״̬����, ����״̬��������״̬
               ����
���:    *header: ����ڵ㣬 ��ӦXML��type�ֶ�֮������ݣ�
                           ���й�������
                *idf_info: ��������ݵĽṹ��
����:  *flag:  ��ʾ�Ƿ��ع���ڵ������������
                        ��������  R_YES
                        ����������   R_NO        
����ֵ:  ��
����: dingdong
ʱ��:2014-4-12
˵��:  
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
������: proc_state
����:   ƥ����״̬���� 
���:    *header: ����ڵ㣬 ��ӦXML��type�ֶ�֮������ݣ�
                           ���й�������
                *idf_info: ��������ݵĽṹ��
                
����:  *flag:  ��ʾ�Ƿ��ع���ڵ������������
                        ��������  R_YES
                        ����������   R_NO        
����ֵ:  R_OK, R_ERROR
����:
ʱ��:2013-11
˵��:  ����priotiry�� ��Щ���岻�壬 ���磬 �����ƥ��
����ʱ�� ��ƥ����priorityΪ1�Ŀ���Э��ţ� �ټ���ƥ��
ʱ�� ƥ����priorityΪ2�Ŀ���Э��ţ� ��ʱ��s_proto_id�Ƿ�
Ӧ���޸�? �������ȼ��� ֵԽС�� �����ȼ�Խ�� ��
��������²�Ӧ���޸�s_proto_id, ���������еĹ��� �޸�
s_proto_id������Щ�����͵�������browsing_app/httpport.xml�е�
�����search_app/baidu.xml�еĹ���
======================================================*/
INT32 proc_state(IDF_HEADER *header, IDF_INFO *idf_info,  UINT8 *flag)
{
	if(NULL == header || NULL == idf_info  || NULL == flag)//�������
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n",__func__);
		return R_ERROR;
	}
	*flag = R_NO;// ��ʼֵ����
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
������: proc_idf_rule
����:   ����Ĺ�������ƥ��
���:    *list_header: ��������Ŀ�ʼ�ڵ�
                *idf_info : ��������ݵĽṹ��
                proto_id: �����������ڵĹ���ͷ�ڵ��е�Э���
����:  *output_flag:  
                       ƥ��ɹ�:  R_YES
                       ƥ�䲻ͨ��:   R_NO
����ֵ:  R_OK, R_ERROR
����:
ʱ��:2013-11
˵��: 
======================================================*/
INT32 proc_idf_rule(void *list_header,  IDF_INFO *idf_info, UINT32 proto_id, UINT8 *output_flag)
{
	T_IDF_RULE  *idf_rule = NULL;
	void *list_node = NULL;
	IDF_TYPE type = 0;
	UINT8 flag = 0;
	if(NULL == idf_info || NULL == output_flag)//�������
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n",__func__);
		return R_ERROR;
	}
	if(NULL == list_header)
	{
		return R_OK;
	}
	list_node = list_header;
	while(NULL != list_node)//��������
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
		else//ָ����һ�ڵ�
		{
			list_node = idf_rule->next;
		}
	}
	*output_flag  = flag;
	return R_OK;
}
/*====================================================
������: get_idf_proto_id
����:   �ӹ�������ȡЭ���
���:   *idf_info : ��������ݵĽṹ��               
����:              
����ֵ:  R_OK, R_ERROR
����:
ʱ��:2013-11
˵��: 
======================================================*/
INT32  get_idf_proto_id(IDF_INFO *idf_info)  
{  
	IDF_TREE_NODE *tree_root = NULL;
	if(NULL == idf_info )//�������
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n",__func__);
		return R_ERROR;
	}
    if (NULL == g_idf_tree)//���������
    {
    	log_message(LOG_ERROR, "%s: idf_tree is NULL.\n", __func__);
        return R_ERROR;
    }
    if (0 == idf_info->status[0])//��ʼ��
    	snprintf(idf_info->status, IDF_MAX_STATU_LEN, "NO_STATUS");

    if (IPPROTO_TCP == idf_info->l4_type) //ѡ����
    	tree_root = g_idf_tree->tcp_tree_root;
	else if(IPPROTO_UDP == idf_info->l4_type)
		tree_root = g_idf_tree->udp_tree_root;
	else
	{//����
		log_message(LOG_ERROR, "%s: idf_info->l4type is wrong. l4type:%d.\n", __func__, idf_info->l4_type);
		return R_ERROR;
	}
	if(R_OK != proc_idf(idf_info, tree_root))//��ȡЭ���
	{
		log_message(LOG_ERROR, "%s: check_cluster_group return R_ERROR.\n", __func__);
		return R_ERROR;
	}
    return R_OK;
}

/*====================================================
������: get_port_proto_id
����:   ���ݶ˿ڻ�ȡЭ���
���:   *idf_info : ��������ݵĽṹ��
����:   *flag: R_NO��ʾ�ҵ�Э��ţ�����������
                R_YES��ʾδ�ҵ�, ��������
����ֵ:  R_OK, R_ERROR
����:
ʱ��:2013-11
˵��: 
======================================================*/
INT32  get_port_proto_id(IDF_INFO *idf_info, UINT8 *flag)
{
    UINT32 sport = 0;
	UINT32 dport = 0;
	UINT32  *port  = NULL;
	UINT8  *port_is_pos = NULL;
	if(NULL == idf_info  || NULL == flag)//�������
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n",__func__);
		return R_ERROR;
	}
	*flag = R_YES;
    if(ntohs(idf_info->sport) < ntohs(idf_info->dport)) //������С�˿��ж�
    {
        sport = idf_info->sport;  
        dport = idf_info->dport;
    }
    else 
    {
        sport = idf_info->dport;  
        dport = idf_info->sport;
    } 
	if (IPPROTO_TCP == idf_info->l4_type) //ȷ��ʹ�õ�����
	{
		port = g_port_proto_tbl.tcp_port;
		port_is_pos = g_port_proto_tbl.tcp_port_is_pos;
	}
	else
	{
		port = g_port_proto_tbl.udp_port;
		port_is_pos = g_port_proto_tbl.udp_port_is_pos;
	}
	if(0 != port[htons(sport)])//�Ƿ�����Ч��Э���
	{
		if(0 != port_is_pos[htons(sport)] || (htons(sport) >= 1024 && htons(sport) != 3306))//����˿ڴ���1024, ��������Ϊ����Э��
		{
			idf_info->s_proto_id = port[htons(sport)];
			idf_info->store_priority = 1;  //�˿ڹ���Ŀ���ֵ�� ���ȼ�����Ϊ1
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
������: print_idf_rule
����:  ��ӡʶ����Ϣ
���:  
����: 
����ֵ:  R_OK, R_ERROR
����:
ʱ��:2013-11
˵��: 
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
������: proc_first_packet
����:  �������еĵ�һ������
���:   *idf_info : ��������ݵĽṹ��
����: 
����ֵ:  R_OK, R_ERROR
����:
ʱ��:2013-11
˵��: 
======================================================*/
INT32 proc_first_packet(IDF_INFO *idf_info, UINT8 *flag)
{
	UINT32 proto_id = 0;
	if(NULL == idf_info)//�������
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n",__func__);
		return R_ERROR;
	}
	*flag = R_YES;
	if (0 == idf_info->pkt_count)
	{
		init_pkt_proto(idf_info);//��ʼ?
	
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
������: init_pkt_proto
����:  ��ʼ��Э�����
���:   *idf_info : ��������ݵĽṹ��
           
����: 
����ֵ:  R_OK, R_ERROR
����:
ʱ��:2013-11
˵��: 
======================================================*/
INT32 init_pkt_proto(IDF_INFO *idf_info)
{
	if(NULL == idf_info)//�������
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
������: proc_ftp_data
����:  ����ftp��̬�˿�����
���:   *idf_info : ��������ݵĽṹ��
����: 
����ֵ:  R_OK, R_ERROR
����:
ʱ��:2013-12
˵��: 
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
������: idf
����:  ����ӿڣ� ��ȡЭ���
���:   *idf_info : ��������ݵĽṹ��
����: 
����ֵ:  R_OK, R_ERROR
����:
ʱ��:2013-11
˵��: 
======================================================*/
INT32 idf(IDF_INFO *idf_info)    
{    
	UINT32 proto_id = 0;
	UINT8 debug_result_flag = RESET_FLAG;
	UINT8 str[G_PRINT_LEN] = {0};
	UINT8 flag = 0;
	UINT8 store_status[IDF_MAX_STATU_LEN] = {0};
	INT32 nopayload_count = 0;
    if(NULL == idf_info)//�������
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
	
	if(debug_switch != 0)//���ӵĵ�����Ϣ
	{
		if((idf_info->payload_count < IDF_PKT_THRESHOLD/2) && 0 == idf_info->proto_id) 
		{
			debug_result_flag = SET_FLAG;
		}
	}
	if (0 == idf_info->proto_id)
	{
    	if (5 > idf_info->pkt_count) //Ϊ���еĵ�һ������
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
    if (0 == idf_info->proto_id) //��δʶ��
    { 
        if (idf_info->payload_count < IDF_PKT_THRESHOLD/2)
        {
        	if(0 != CHECK_BIT(idf_info->state, IDF_STATE_USE_STATUS))//�ж��Ƿ�ʹ����״̬��
        	{
        		if(0 == strlen(idf_info->status))
        		{
        			log_message(LOG_ERROR, "%s: idf_info->state may be wrong, please check it .\n", __func__);
					return R_ERROR;

        		}
        		snprintf(store_status, IDF_MAX_STATU_LEN, idf_info->status);//���浱ǰ�Ѿ������״̬
				idf_info->terminal_id = 0;
			}
			
            if(R_OK != get_idf_proto_id(idf_info))//����ʶ����
            {
            	log_message(LOG_ERROR,"%s: get_proto_id return R_ERROR.\n", __func__);
				idf_info->state = 0;//����ʱ�� �����еĵ�״̬ȫ���
				return R_ERROR;
            }

			idf_info->state = RESET_BIT(idf_info->state, IDF_STATE_CURRENT_STATUS);//�˳�get_idf_proto_id�� IDF_STATE_CURRENT_STATUSλ��0
			if(0 !=  CHECK_BIT(idf_info->state, IDF_STATE_USE_STATUS))//�ж��Ƿ�ʹ����״̬��
			{
				if(0 == strcmp(idf_info->status, store_status))//���״̬û�иı䣬 ��״̬��ʧЧ
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
	if(debug_switch != 0)//���ӵĵ�����Ϣ
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
������: init_tree
����:  ��ʼ����
���:   node_len: ���飬 ���ڵ��еĳ��ȣ�-1 ��ʾ��Ч
              �������Ŀ
����: **tree_root:  �������Ժ�����ĸ��ڵ�
����ֵ:  R_OK, R_ERROR
����:
ʱ��:2013-11
˵��: 
======================================================*/
INT32  init_tree(IDF_TREE_NODE **tree_root, INT32 node_len[], INT32 node_num)
{
	INT32 i = 0;
	INT32 j = 0;
	IDF_TREE_NODE *node_ptr0 = NULL;
	IDF_TREE_NODE *node_ptr1 = NULL;
	IDF_TREE_NODE **tree_node = NULL;
	if(NULL == node_len || node_num <= 0)//�������
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n",__func__);
		return R_ERROR;
	}
	if(NULL ==(tree_node = i_calloc(node_num ,sizeof(void *), I_IDF, 0)))//����ռ�
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
            else  //i=0��ʾ���������
            {
                *tree_root = node_ptr0;
            }
		}
	}
	i_free(tree_node);
	return R_OK;
}
/*====================================================
������: init_identifier_map
����:  ��ʼ��������ȡxml�ļ��� ��ʼ��AC
���:    *idf_tree : �ṹ��ָ�룬 ����tcp���� udp���� �˿�Э��
                               ӳ���
                list: �ļ���
����: 
����ֵ:  R_OK, R_ERROR
����:
ʱ��:2013-11
˵��: 
======================================================*/
INT32 init_identifier_map(IDF_TREE *idf_tree, INT8 *list)  
{
    INT32 i = 0;
	INT32 j = 0;
    IDF_FILE_LIST  name_list = {0};    /*�ͽṹ��namelist���� */
    FILE  *p = NULL; 
    INT32 tcp_node_plen[16] = {184,68,731,34,96,280,-1,6,60,-1,-1,246,-1,-1,-1,-1};
	INT32 udp_node_plen[16] = {394,44,1079,29,-1,760,-1,22,-1,-1,-1,-1,-1,-1,-1,-1};
	INT8 file_path[IDF_MAX_FILE_NAME_LEN] = {0};
	INT8 log_str[G_LOG_LEN] = {0};
	if(NULL == list)//�������
	{
		log_message(LOG_ERROR, "%s: Parameter(s) error.\n",__func__);
		return R_ERROR;
	}
	if(R_OK != init_tree(&(idf_tree->tcp_tree_root), tcp_node_plen, 16))//��ʼ�� tcp������
	{
		log_message(LOG_ERROR, "%s: init_tree return R_ERROR.\n", __func__);
		return R_ERROR;
	}
	if(R_OK != init_tree(&(idf_tree->udp_tree_root), udp_node_plen, 16))//��ʼ�� udp������
	{
		free_idf_tree(idf_tree->tcp_tree_root, 16);
		log_message(LOG_ERROR, "%s: init_tree return R_ERROR.\n", __func__);
		return R_ERROR;
	}
    
    // ��ȡ�ļ����õ�Ҫʶ��Э���б�Ͷ�Ӧ���ļ�·��
    p = fopen(list, "r");
    if (NULL == p) //���ļ�ʧ��ʱ�� �ͷ�ǰ��Ŀռ�
    {
    	free_idf_tree(idf_tree->tcp_tree_root, 16);
		free_idf_tree(idf_tree->udp_tree_root, 16);
    	log_message(LOG_ERROR, "%s: p = fopen(list, \"r\") is NULL.\n", __func__);
		return R_ERROR;
    }
    else 
    {
        fscanf(p, "number:%d\n", &name_list.xml_file_num);// ��ȡxml���ļ�����
        for (i = 0; i < name_list.xml_file_num; i++) //ѭ����ȡxml�ļ�
        {
        	if (i >= idf_read_xml_num && idf_read_xml_num != 0)
			{
				break;
			}
            fscanf(p, "%s\n", name_list.file_path[i]);// ��ȡ�ļ����� ����û�й��˵�ǰ��ո� ��βһ����Ϊ
												      //'\n���������βΪ'\r\n��,������������
			//log_message(LOG_INFO, "file_num:%d, %s\n", i + 1, name_list.file_path[i]);

			if (0 != access(name_list.file_path[i],0) && SET_FLAG != g_license_flag)//�ļ������ڣ� ��Ϊ�����ļ�
			{
				 snprintf(file_path,IDF_MAX_FILE_NAME_LEN,"%s.ss",name_list.file_path[i]);  
			} 
			else 
			{	
				snprintf(file_path,IDF_MAX_FILE_NAME_LEN,"%s",name_list.file_path[i]);
			}
            if(R_OK != read_xml(file_path, idf_tree))//��ȡ
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
������: proc_ac
����:  ���ݶ�ȡ��string��url, char�ȣ������ģƥ���㷨��
���:    
����: 
����ֵ:  R_OK, R_ERROR
����:
ʱ��:2013-11
˵��: 
======================================================*/
INT32 proc_ac(void)
{
	INT32 i = 0;
	IDF_AC_STRING *temp = NULL;
	g_acsm = acsmNew();//AC��ʼ��
	temp = g_ac_string;
	while(NULL != temp)
	{
		acsmAddPattern(g_acsm, temp, g_pattern_num);
		g_pattern_num++;
		temp = temp->next;
	}
    acsmCompile (g_acsm);//����
    return R_OK;
}
/*====================================================
������: free_identifier_header_list
����:  �ͷ�Э��ͷ����
���:    list_header: ͷָ��
����: 
����ֵ:  R_OK, R_ERROR
����:
ʱ��:2013-11
˵��: 
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
		while(NULL != cluster)// �ͷŹ���ͷ�ڵ��еľ�����������
		{
			temp_cluster = cluster;
			cluster = cluster->next;
			i_free(temp_cluster);
		}
		temp_node = node;//  �ͷŹ���ͷ����
		node = node->next;
		i_free(temp_node);
	}
	return R_OK;
}
/*====================================================
������: free_idf_tree
����:  �ͷ�Э�������
���:    tree_root: ���ĸ��ڵ�
                node_num:�ڵ����,��ջ�����ֵ
����: 
����ֵ:  R_OK, R_ERROR
����:
ʱ��:2013-11
˵��:  ʹ�õݹ������
======================================================*/
INT32 free_idf_tree(IDF_TREE_NODE*tree_root, INT32 node_num)
{
	IDF_TREE_NODE **stack;
	INT32 i = 0;
	IDF_TREE_NODE *node_ptr = NULL; 
	if(NULL == tree_root || node_num <= 0)
		return R_OK;
	if(NULL == (stack = i_malloc(sizeof(void *) * node_num, I_IDF, 0)))//�����ջ
	{
		log_message(LOG_ERROR,  "%s: No memory.\n");
		return R_ERROR;
	}
	memset(stack, 0 , sizeof(void *) * node_num);//��0
	stack[0] = tree_root;//�ڶ�ջ�з�����ڵ�
	for(i = 0;i < node_num && stack[i] != NULL;)
	{
		node_ptr = stack[i--];//�ڶ�ջ��ȡ�ڵ�
        if (node_ptr->left_small != NULL)
        {
            stack[++i] = node_ptr->left_small; //���ջ
        }
        else 
        {
            if (node_ptr->left_header != NULL)
            {
                free_idf_header_list(node_ptr->left_header);//�ͷ�������
            }
        }
        
        if (node_ptr->right_big != NULL)
        {
            stack[++i] = node_ptr->right_big;//���ջ
        }
        else 
        {
            if (node_ptr->right_header != NULL)
            {
                free_idf_header_list(node_ptr->right_header);//�ͷ�������
            }
        }
		i_free(node_ptr);//�ͷ����ڵ�
        if (i < 0)//��ջΪ���ˣ� �Ѿ�������
        {
            break;
        }
	}
	i_free(stack);
	return R_OK;
}
/*====================================================
������: free_idf_map
����:  �ͷ�tcp����udp��
���:     *idf_tree : �ṹ��ָ�룬 ����tcp���� udp���� �˿�
               Э��ӳ���
����: 
����ֵ:  R_OK, R_ERROR
����:dingdong
ʱ��:2013-11
˵��: 
======================================================*/
INT32 free_idf_map(IDF_TREE  *idf_tree)
{
    if(NULL == idf_tree)
		return R_OK;
	if(NULL != idf_tree->tcp_tree_root)
	{
		free_idf_tree(idf_tree->tcp_tree_root, 16); //�ͷŽṹ���� ��tcp������
	}
	if(NULL != idf_tree->udp_tree_root)
	{
		free_idf_tree(idf_tree->udp_tree_root, 16);//�ͷŽṹ�����UDP������
	}
	i_free(idf_tree);
	return R_OK;
}
/*====================================================
������: free_port_ip_tbl
����:  �ͷ�port_ip��Ŀռ�
���:    *input_tbl: port_ip��
����: 
����ֵ:  R_OK, R_ERROR
����:dingdong
ʱ��:2013-11
˵��: 
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
������: clear_port_ip_tbl
����:  ���port_ip��Ŀռ�
���:    *input_tbl: port_ip��
����: 
����ֵ:  
����:
ʱ��:
˵��: 
======================================================*/
void clear_port_ip_tbl()
{
	INT32 i = 0 , j = 0;
    IDF_IP_PROTO_NODE *pip = NULL, *pip_prev = NULL, *temp_pip = NULL;
    if (NULL == g_port_ip_tbl || NULL == g_port_ip_tbl->free_node) //���
    {
    	log_message(LOG_ERROR, "%s: g_port_ip_tbl or g_port_ip_tbl->free_node is NULL.\n", __func__);
        return;
    }
    
    pthread_rwlock_wrlock(&g_port_ip_tbl->lock);//ȫ��ס
    for (i = 0; i < IDF_PORT_NUM; i++) //һ��һ��Ͱ����
    {
		pip = g_port_ip_tbl->node_index[i];
        pip_prev = NULL;
        while (pip) //ѭ������Ͱ�µ�����
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
     pthread_rwlock_unlock(&g_port_ip_tbl->lock);//����
       
}

/*====================================================
������: free_ac_string
����:  �ͷ�ac_string����ռ�
���:    *input_list: ���ͷŵ�����ͷ
����: 
����ֵ:  R_OK, R_ERROR
����:dingdong
ʱ��:2013-11
˵��: 
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
������: free_ip_hash_tbl
����:  �ͷ�ip hash��Ŀռ�
���:    *input_tbl: ���ͷŵı�
����: 
����ֵ:  R_OK, R_ERROR
����:dingdong
ʱ��:2013-11
˵��: 
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
������: free_idf_resource
����:  �ͷ����е���Դ
���:    
����: 
����ֵ:  R_OK, R_ERROR
����:dingdong
ʱ��:2013-11
˵��: 
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
������: init_special_string
����:  ��ʼ��g_ac_string, �����в��������ַ�����Ӧ�Ľڵ�
���:    
����: 
����ֵ:  R_OK, R_ERROR
����:dingdong
ʱ��:2013-11
˵��: 
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
������: init_idf
����:  �ܳ�ʼ�������� ����ӿ�
���:     
����: 
����ֵ:  R_OK, R_ERROR
����:dingdong
ʱ��:2013-11
˵��:  
======================================================*/
INT32 init_idf(void)  
{
	INT8 time_str[TIME_LENGTH] = {0};
	pthread_t check_thread = {0};
	if (R_OK != decrypt_license_ss()) 
	{
		g_license_flag = SET_FLAG;
	}
	if(SET_FLAG != g_license_flag)//����license.ss�ɹ��� ��ִ��
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
	get_cfg();// ��ȡ������Ϣ
	free_idf_resource();//�ͷ����е����ݿռ�
	if(0 == g_init_count_num)  //��һ�γ�ʼ��ʱ����
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
	if(NULL == (g_idf_tree = i_calloc(sizeof(IDF_TREE), 1, I_IDF, 0)))  //����ռ�
    {
    	log_message(LOG_ERROR, "%s: No memory.\n", __func__);
		return R_ERROR;
    }
    if(R_OK != init_identifier_map(g_idf_tree, IDF_PROTO_LIST_FILE))//��ʼ����
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
������: get_cfg
����:  �������ļ��л�ȡ��Ҫ������ֵ
���:    
����:
����ֵ:  
����:
ʱ��:2013-10-25
˵��: 
======================================================*/
void get_cfg(void)
{
	INT8 cfg_file_content[G_MAX_CFG_LEN] = {0};
	INT8 switch_item[] = "log_switch";
	INT8 level_item[] = "log_level";
	UINT8 flag = 0;
	INT32 result = 0;
	if(R_OK != get_cfg_file_content(g_cfg_file_name, cfg_file_content, G_MAX_CFG_LEN))
	{// ������ܴ������ļ����������ļ������⣬ ʹ��Ĭ��ֵ
		//log_message(LOG_ERROR, "%s: get_cfg_file_content return R_ERROR.\n", __func__);
		debug_switch = 0;
		debug_print_level = 1;
		return;
	}
	if(R_OK != get_cfg_int(cfg_file_content, switch_item, &result, &flag))//��ȡlog_switch
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
	if(R_OK != get_cfg_int(cfg_file_content, level_item, &result, &flag))//��ȡlog_level
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
������: check_payload_first_byte
����:   �жϸ����ĸ��ص�һ���ֽ��Ƿ�Ϊ0x24
���:    *packet_payload: ����
         *packet_length: ���س���
                
����:  ��        
����ֵ:  R_OK, R_ERROR
����:
ʱ��:2013-11
˵��: 
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
/* ��������������ֱ�ӴӸ�����Ŀ¼�¶�ȡ
��Ŀ¼�����е�xml�ļ�������������Ҫ��
protocol.lst�ļ��ж�ȡxml�ļ����� */
/*
#define    IDF_PROTO_LIST_FILE   "./protocol_identifier_xml_file"
#define FILE_PATH_LENGTH 256 
====================================================
������: trave_dir
����:   ��������Ŀ¼�����е��ļ���������
���:    *path: Ŀ¼��
         *idf_tree: ������
                
����:  ��        
����ֵ:  R_OK, R_ERROR
����:
ʱ��:2013-11
˵��: 
======================================================
int trave_dir(char *path, IDF_TREE *idf_tree)
{
	DIR *dir_ptr;     				// ����Ŀ¼���͵�ָ��                
	struct dirent *direntp;       	// �������ڶ�Ŀ¼�Ļ�����
	struct stat sb;
	char absolute_path[FILE_PATH_LENGTH];
	char temp_path[FILE_PATH_LENGTH];
	
    if (path == NULL || idf_tree == NULL)
	{
		return R_ERROR;
	}
	// ת���ɾ���·�� 
	if (realpath(path, absolute_path) == NULL)
	{
		printf("transform fail\n");
		return R_ERROR;
	}
	if ((dir_ptr = opendir(absolute_path)) == NULL) 
	{		
		printf("Can��t open!\n");
		return R_ERROR;
	}
	
    while ((direntp = readdir(dir_ptr)) != NULL) 
	{
        //�ѵ�ǰĿ¼.����һ��Ŀ¼..�������ļ���ȥ��
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
������: decrypt_license_ss
����:	��licence.ss �н���
���:	��				
����:  ��		 
����ֵ:  R_OK, R_ERROR
����:
ʱ��:2014-01
˵��: 
======================================================*/
INT32 decrypt_license_ss()
{
	INT8 *output = NULL;
	struct AVDES des = {0};
	UINT32 len = 0;
	UINT32 num = 0;
	UINT8 key[] = {0x14, 0x34, 0x56, 0x78, 0x9a, 0xb5, 0xde, 0xf0};
	if(0 != access("license.ss", 0))//�ж�license.ss�Ƿ����
	{
		g_license_flag = SET_FLAG; //����ȫ�ֱ�ʶ
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
������: allocate_des_memory
����:	Ϊ�ļ������ڴ�
���:	filename �ļ���
		len �ļ�����
����:  ��		 
����ֵ:  �ɹ����ص�ַ��ʧ�ܷ���NULL
����:
ʱ��:2014-01
˵��: 
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
������: verify_password_information
����:	��֤������Ϣ
���:	��				
����:  ��		 
����ֵ:  R_OK, R_ERROR
����:
ʱ��:2014-01
˵��: 
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
������: get_license_information
����:	���ַ�������ȡ����
���:	des Ŀ���ַ���			
����:  str_start Ҫ��ǰ���ַ�����ʼ
		 str_end Ҫ��ȡ���ַ�������
����ֵ:  
����:
ʱ��:2014-01
˵��: 
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
������: get_information
����:	���ַ�������ȡ����
���:	des Ŀ���ַ���			
����:  output �ַ���
����ֵ: R_OK,R_ERROR 
����:
ʱ��:2014-01
˵��: 
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
������: decrypt
����:	���ļ��н���
���:	temp_path �ļ�·��			
����:  content ���ܺ������
		 content_len ���ܺ�����ݳ���
����ֵ:  R_OK, R_ERROR
����:
ʱ��:2014-01
˵��: 
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
������: idf_get_version_str
����:	���ذ汾�ţ� �������еط�����Ҫ��
             ����δ����ӿ�idf.h��, ��icare����
���:			
����: 
����ֵ:  �汾��
����:
ʱ��:2014-03
˵��: 
======================================================*/
INT8 *idf_get_version_str(void)
{
	return IDF_VERSION;
}
/*====================================================
������: idf_get_version
����:	���ذ汾�Ŷ�Ӧ�����֣� �������еط�����Ҫ��
             ����δ����ӿ�idf.h��, ��icare����
���:			
����: 
����ֵ:  �汾��
����:
ʱ��:2014-03
˵��:   ���ֵļ��㷽���� ��3.0.7�� Ϊ
3 * 10000 + 0 * 100 + 7 , Ϊ���㣬 ��Ϊֱ����дIDF_VERSION_NUM
======================================================*/
UINT32 idf_get_version(void)
{
	return IDF_VERSION_NUM;
}

