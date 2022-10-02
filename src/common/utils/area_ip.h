//
// Created by System Administrator on 2020/10/8.
//

#ifndef ST_AREAIP_UTILS_H
#define ST_AREAIP_UTILS_H

#include "ipv4.h"
#include "logger.h"
#include "shell.h"
#include "string_utils.h"
#include <iostream>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

using namespace std;

namespace st {
    namespace areaip {
        class area_ip_range {
        public:
            uint32_t start = 0;
            uint32_t end = 0;
            string area;

            string serialize() const { return to_string(start) + "\t" + to_string(end) + "\t" + area; }

            bool is_valid() const { return area.size() == 2 && end >= start && start != 0; }

            static area_ip_range parse(const string &str) {
                area_ip_range result;
                auto strs = st::utils::strutils::split(str, "\t");
                if (strs.size() == 3) {
                    try {
                        result.start = stoul(strs[0]);
                        result.end = stoul(strs[1]);
                        result.area = strs[2];
                    } catch (const std::exception &e) {
                        st::utils::logger::ERROR << "area_ip_range parse error!" << str << e.what() << END;
                    }
                }
                return result;
            }
            static area_ip_range parse(const string &rangeStr, const string &area) {
                area_ip_range result;
                uint64_t index = rangeStr.find_first_of('/');
                result.start = st::utils::ipv4::str_to_ip(rangeStr.substr(0, index));
                uint32_t ipNum = 1 << (32 - atoi(rangeStr.substr(index + 1, rangeStr.length()).c_str()));
                result.end = result.start + ipNum - 1;
                result.area = area;
                return result;
            }
        };
        uint16_t area_to_code(const string &areaCode);
        string code_to_area(uint16_t mark);
        class manager {
        public:
            manager();
            ~manager();
            bool load_area_ips(const string &areaCode);
            bool is_area_ip(const string &areaReg, const uint32_t &ip);
            bool is_area_ip(const vector<string> &areas, const uint32_t &ip);
            bool is_area_ip(const string &areaReg, const string &ip);
            string get_area(const uint32_t &ip);
            pair<string, vector<area_ip_range>> load_ip_info(const uint32_t &ip);
            static manager &uniq();

        private:
            const string CN_CODE_JSON =
                    "{\"阿富汗\": \"AF\", \"奥兰\": \"AX\", \"阿尔巴尼亚\": \"AL\", \"阿尔及利亚\": \"DZ\", "
                    "\"美属萨摩亚\": \"AS\", \"安道尔\": \"AD\", \"安哥拉\": \"AO\", \"安圭拉\": \"AI\", \"南极洲\": "
                    "\"AQ\", \"安提瓜和巴布达\": \"AG\", \"阿根廷\": \"AR\", \"亚美尼亚\": \"AM\", \"阿鲁巴\": \"AW\", "
                    "\"澳大利亚\": \"AU\", \"奥地利\": \"AT\", \"阿塞拜疆\": \"AZ\", \"巴哈马\": \"BS\", \"巴林\": "
                    "\"BH\", \"孟加拉国\": \"BD\", \"巴巴多斯\": \"BB\", \"白俄罗斯\": \"BY\", \"比利时\": \"BE\", "
                    "\"伯利兹\": \"BZ\", \"贝宁\": \"BJ\", \"百慕大\": \"BM\", \"不丹\": \"BT\", \"玻利维亚\": \"BO\", "
                    "\"荷兰加勒比区\": \"BQ\", \"波黑\": \"BA\", \"博茨瓦纳\": \"BW\", \"布韦岛\": \"BV\", \"巴西\": "
                    "\"BR\", \"英属印度洋领地\": \"IO\", \"文莱\": \"BN\", \"保加利亚\": \"BG\", \"布基纳法索\": "
                    "\"BF\", \"布隆迪\": \"BI\", \"佛得角\": \"CV\", \"柬埔寨\": \"KH\", \"喀麦隆\": \"CM\", "
                    "\"加拿大\": \"CA\", \"开曼群岛\": \"KY\", \"中非\": \"CF\", \"乍得\": \"TD\", \"智利\": \"CL\", "
                    "\"中国\": \"CN\", \"圣诞岛\": \"CX\", \"科科斯（基林）群岛\": \"CC\", \"哥伦比亚\": \"CO\", "
                    "\"科摩罗\": \"KM\", \"刚果共和国\": \"CG\", \"刚果民主共和国\": \"CD\", \"库克群岛\": \"CK\", "
                    "\"哥斯达黎加\": \"CR\", \"科特迪瓦\": \"CI\", \"克罗地亚\": \"HR\", \"古巴\": \"CU\", \"库拉索\": "
                    "\"CW\", \"塞浦路斯\": \"CY\", \"捷克\": \"CZ\", \"丹麦\": \"DK\", \"吉布提\": \"DJ\", "
                    "\"多米尼克\": \"DM\", \"多米尼加\": \"DO\", \"厄瓜多尔\": \"EC\", \"埃及\": \"EG\", \"萨尔瓦多\": "
                    "\"SV\", \"赤道几内亚\": \"GQ\", \"厄立特里亚\": \"ER\", \"爱沙尼亚\": \"EE\", \"斯威士兰\": "
                    "\"SZ\", \"埃塞俄比亚\": \"ET\", \"福克兰群岛\": \"FK\", \"法罗群岛\": \"FO\", \"斐济\": \"FJ\", "
                    "\"芬兰\": \"FI\", \"法国\": \"FR\", \"法属圭亚那\": \"GF\", \"法属波利尼西亚\": \"PF\", "
                    "\"法属南部和南极领地\": \"TF\", \"加蓬\": \"GA\", \"冈比亚\": \"GM\", \"格鲁吉亚\": \"GE\", "
                    "\"德国\": \"DE\", \"加纳\": \"GH\", \"直布罗陀\": \"GI\", \"希腊\": \"GR\", \"格陵兰\": \"GL\", "
                    "\"格林纳达\": \"GD\", \"瓜德罗普\": \"GP\", \"关岛\": \"GU\", \"危地马拉\": \"GT\", \"根西\": "
                    "\"GG\", \"几内亚\": \"GN\", \"几内亚比绍\": \"GW\", \"圭亚那\": \"GY\", \"海地\": \"HT\", "
                    "\"赫德岛和麦克唐纳群岛\": \"HM\", \"梵蒂冈\": \"VA\", \"洪都拉斯\": \"HN\", \"香港\": \"HK\", "
                    "\"匈牙利\": \"HU\", \"冰岛\": \"IS\", \"印度\": \"IN\", \"印尼\": \"ID\", \"伊朗\": \"IR\", "
                    "\"伊拉克\": \"IQ\", \"爱尔兰\": \"IE\", \"马恩岛\": \"IM\", \"以色列\": \"IL\", \"意大利\": "
                    "\"IT\", \"牙买加\": \"JM\", \"日本\": \"JP\", \"泽西\": \"JE\", \"约旦\": \"JO\", \"哈萨克斯坦\": "
                    "\"KZ\", \"肯尼亚\": \"KE\", \"基里巴斯\": \"KI\", \"朝鲜\": \"KP\", \"韩国\": \"KR\", \"科威特\": "
                    "\"KW\", \"吉尔吉斯斯坦\": \"KG\", \"老挝\": \"LA\", \"拉脱维亚\": \"LV\", \"黎巴嫩\": \"LB\", "
                    "\"莱索托\": \"LS\", \"利比里亚\": \"LR\", \"利比亚\": \"LY\", \"列支敦士登\": \"LI\", \"立陶宛\": "
                    "\"LT\", \"卢森堡\": \"LU\", \"澳门\": \"MO\", \"马达加斯加\": \"MG\", \"马拉维\": \"MW\", "
                    "\"马来西亚\": \"MY\", \"马尔代夫\": \"MV\", \"马里\": \"ML\", \"马耳他\": \"MT\", \"马绍尔群岛\": "
                    "\"MH\", \"马提尼克\": \"MQ\", \"毛里塔尼亚\": \"MR\", \"毛里求斯\": \"MU\", \"马约特\": \"YT\", "
                    "\"墨西哥\": \"MX\", \"密克罗尼西亚联邦\": \"FM\", \"摩尔多瓦\": \"MD\", \"摩纳哥\": \"MC\", "
                    "\"蒙古\": \"MN\", \"黑山\": \"ME\", \"蒙特塞拉特\": \"MS\", \"摩洛哥\": \"MA\", \"莫桑比克\": "
                    "\"MZ\", \"缅甸\": \"MM\", \"纳米比亚\": \"NA\", \"瑙鲁\": \"NR\", \"尼泊尔\": \"NP\", \"荷兰\": "
                    "\"NL\", \"新喀里多尼亚\": \"NC\", \"新西兰\": \"NZ\", \"尼加拉瓜\": \"NI\", \"尼日尔\": \"NE\", "
                    "\"尼日利亚\": \"NG\", \"纽埃\": \"NU\", \"诺福克岛\": \"NF\", \"北马其顿\": \"MK\", "
                    "\"北马里亚纳群岛\": \"MP\", \"挪威\": \"NO\", \"阿曼\": \"OM\", \"巴基斯坦\": \"PK\", \"帕劳\": "
                    "\"PW\", \"巴勒斯坦\": \"PS\", \"巴拿马\": \"PA\", \"巴布亚新几内亚\": \"PG\", \"巴拉圭\": \"PY\", "
                    "\"秘鲁\": \"PE\", \"菲律宾\": \"PH\", \"皮特凯恩群岛\": \"PN\", \"波兰\": \"PL\", \"葡萄牙\": "
                    "\"PT\", \"波多黎各\": \"PR\", \"卡塔尔\": \"QA\", \"留尼汪\": \"RE\", \"罗马尼亚\": \"RO\", "
                    "\"俄罗斯\": \"RU\", \"卢旺达\": \"RW\", \"圣巴泰勒米\": \"BL\", "
                    "\"圣赫勒拿、阿森松和特里斯坦-达库尼亚\": \"SH\", \"圣基茨和尼维斯\": \"KN\", \"圣卢西亚\": "
                    "\"LC\", \"法属圣马丁\": \"MF\", \"圣皮埃尔和密克隆\": \"PM\", \"圣文森特和格林纳丁斯\": \"VC\", "
                    "\"萨摩亚\": \"WS\", \"圣马力诺\": \"SM\", \"圣多美和普林西比\": \"ST\", \"沙特阿拉伯\": \"SA\", "
                    "\"塞内加尔\": \"SN\", \"塞尔维亚\": \"RS\", \"塞舌尔\": \"SC\", \"塞拉利昂\": \"SL\", \"新加坡\": "
                    "\"SG\", \"荷属圣马丁\": \"SX\", \"斯洛伐克\": \"SK\", \"斯洛文尼亚\": \"SI\", \"所罗门群岛\": "
                    "\"SB\", \"索马里\": \"SO\", \"南非\": \"ZA\", \"南乔治亚和南桑威奇群岛\": \"GS\", \"南苏丹\": "
                    "\"SS\", \"西班牙\": \"ES\", \"斯里兰卡\": \"LK\", \"苏丹\": \"SD\", \"苏里南\": \"SR\", "
                    "\"斯瓦尔巴和扬马延\": \"SJ\", \"瑞典\": \"SE\", \"瑞士\": \"CH\", \"叙利亚\": \"SY\", \"台湾\": "
                    "\"TW\", \"塔吉克斯坦\": \"TJ\", \"坦桑尼亚\": \"TZ\", \"泰国\": \"TH\", \"东帝汶\": \"TL\", "
                    "\"多哥\": \"TG\", \"托克劳\": \"TK\", \"汤加\": \"TO\", \"特立尼达和多巴哥\": \"TT\", \"突尼斯\": "
                    "\"TN\", \"土耳其\": \"TR\", \"土库曼斯坦\": \"TM\", \"特克斯和凯科斯群岛\": \"TC\", \"图瓦卢\": "
                    "\"TV\", \"乌干达\": \"UG\", \"乌克兰\": \"UA\", \"阿联酋\": \"AE\", \"英国\": \"GB\", \"美国\": "
                    "\"US\", \"美国本土外小岛屿\": \"UM\", \"乌拉圭\": \"UY\", \"乌兹别克斯坦\": \"UZ\", \"瓦努阿图\": "
                    "\"VU\", \"委内瑞拉\": \"VE\", \"越南\": \"VN\", \"英属维尔京群岛\": \"VG\", \"美属维尔京群岛\": "
                    "\"VI\", \"瓦利斯和富图纳\": \"WF\", \"西撒哈拉\": \"EH\", \"也门\": \"YE\", \"赞比亚\": \"ZM\", "
                    "\"津巴布韦\": \"ZW\"}";
            const string IP_NET_AREA_FILE = "/etc/area-ips/IP_NET_AREA";
            unordered_map<string, string> CN_AREA_2_AREA;
            unordered_map<string, vector<area_ip_range>> default_caches;
            unordered_map<uint32_t, string> net_caches;
            mutex default_lock;
            mutex net_lock;

            boost::asio::io_context *ctx;
            boost::asio::io_context::work *ctx_work = nullptr;
            std::thread *th = nullptr;
            boost::asio::deadline_timer *stat_timer;
            bool is_area_ip(const string &areaCode, const uint32_t &ip,
                            unordered_map<string, vector<area_ip_range>> &caches);
            string get_area(const uint32_t &ip, unordered_map<string, vector<area_ip_range>> &caches);
            string get_area(const uint32_t &ip, unordered_map<uint32_t, string> &caches);
            string get_area_code(const string &areaReg);
            string download_area_ips(const string &areaCode);
            void async_load_ip_info(const uint32_t &ip);
            void sync_net_area_ip();
            void init_area_code_name_map();
        };
    }// namespace areaip
}// namespace st


#endif//ST_AREAIP_UTILS_H
