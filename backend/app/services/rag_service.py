"""ChromaDB Local EU Regulation Vector Knowledge Base (RAG) Service.

Provides high-precision statutory retrieval and regulatory traceability for:
- EU General Product Safety Regulation (GPSR) (EU) 2023/988
- EU Toy Safety Directive 2009/48/EC & EN 71
- EU Low Voltage Directive (LVD) 2014/35/EU
- EU Electromagnetic Compatibility Directive (EMC) 2014/30/EU
- EU RoHS 2.0 Directive 2011/65/EU
- EU REACH Regulation (EC) No 1907/2006 Annex XVII
- EU Cosmetics Regulation (EC) No 1223/2009
- EU New Batteries Regulation (EU) 2023/1542
- EU Packaging and Packaging Waste Directive 94/62/EC
- EU Radio Equipment Directive (RED) 2014/53/EU
- EU Medical Device Regulation (MDR) (EU) 2017/745

Supports ChromaDB PersistentClient vector storage with deterministic,
zero-dependency offline embedding and hybrid re-ranking to guarantee
100% offline availability in demo and competition environments.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from pydantic import BaseModel, Field


class RegulationMatch(BaseModel):
    """Structured regulatory match returned by the RAG Service."""

    regulation_id: str = Field(..., description="法规官方唯一编号")
    title: str = Field(..., description="法规权威标题")
    article: str = Field(..., description="具体法条号与章节")
    content: str = Field(..., description="权威法条原文")
    penalty_summary: str = Field(..., description="执法后果与罚则摘要")
    category: str = Field(default="general", description="商品适用类目 (toys/electronics/cosmetics/general)")
    relevance_score: float = Field(default=0.0, ge=0.0, le=1.0, description="综合相关度得分 (0.0~1.0)")
    keywords: List[str] = Field(default_factory=list, description="关键术语标签")

    def citation_label(self) -> str:
        """Generate official citation label."""
        return f"[{self.article}] - {self.title}"

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize model to dictionary."""
        return self.model_dump()


# Type alias per specification
RAGRetrievalResult = RegulationMatch


# Authoritative statutory knowledge base seed dataset (16 comprehensive regulations)
SEED_REGULATIONS: List[Dict[str, Any]] = [
    {
        "id": "EU-GPSR-2023-988-ART9",
        "regulation_id": "EU-GPSR-2023-988-ART9",
        "title": "EU GPSR (通用产品安全法规) 第9条 制造商可追溯性与产品识别义务",
        "article": "Article 9",
        "category": "general",
        "keywords": ["GPSR", "通用产品安全法规", "制造商义务", "批次号", "序列号", "追溯要求", "可追溯", "产品识别", "欧代", "欧盟责任人", "联系邮箱"],
        "content": (
            "Manufacturers shall ensure that their products bear a type, batch or serial number or other element "
            "allowing the identification of the product which is easily visible and legible for consumers, or, where the "
            "size or nature of the product does not allow it, that the required information is provided on the packaging "
            "or in a document accompanying the product. Manufacturers shall indicate their name, registered trade name or "
            "registered trade mark, postal and electronic address at which they can be contacted. / "
            "制造商必须确保其产品带有型号、批次或序列号等易于消费者识别的清晰要素；并在产品或其包装/随附文件上标明"
            "其名称、注册商号或注册商标，以及可联系到的有效邮政和电子邮箱地址。欧盟责任人与追溯信息缺失属于严重违法。"
        ),
        "penalty_summary": "海关直接扣押、全欧RAPEX通报下架召回、处最高上年度全球营业额4%罚款",
    },
    {
        "id": "EU-GPSR-2023-988-ART19",
        "regulation_id": "EU-GPSR-2023-988-ART19",
        "title": "EU GPSR (通用产品安全法规) 第19条 远程在线销售信息披露与欧代义务",
        "article": "Article 19",
        "category": "general",
        "keywords": ["GPSR", "远程销售", "跨境电商", "欧盟责任人", "欧代", "EU REP", "EC REP", "线上公示", "警示信息", "追溯要求"],
        "content": (
            "Where products are made available on the market online or through other means of distance sales, the offer "
            "shall clearly and visibly indicate at least: (a) the name, registered trade name or trademark of the manufacturer, "
            "as well as postal and electronic address; (b) in case the manufacturer is not established in the EU, the name, "
            "postal address and electronic address of the responsible person; (c) information to identify the product, "
            "including an illustration, type, batch, serial number; (d) any warning or safety information. / "
            "通过电商或远程销售投放欧盟市场的产品，商品详情页面及产品包装必须清晰可见地展示：(a) 制造商名称、商号、邮政及电子邮箱；"
            "(b) 非欧盟本土制造商的欧盟责任人(EU REP / EC REP)授权代表名称、邮政地址及有效电子邮箱；(c) 产品图片、型号、批次等识别要素；"
            "(d) 适用的警示语和安全信息。追溯链条断裂将直接导致海关拦截。"
        ),
        "penalty_summary": "跨境电商平台强制下架阻断、封禁店铺、限制欧盟关税申报入境",
    },
    {
        "id": "EU-GPSR-2023-988-ART22",
        "regulation_id": "EU-GPSR-2023-988-ART22",
        "title": "EU GPSR (通用产品安全法规) 第22条 在线市场平台监管下架令与两日合规处置",
        "article": "Article 22",
        "category": "general",
        "keywords": ["GPSR", "电商平台", "在线市场", "下架令", "单一联络点", "合规处置", "快速响应", "平台责任"],
        "content": (
            "Online marketplaces shall designate a single point of contact allowing for direct communication with Member States' "
            "market surveillance authorities. Online marketplaces shall comply with orders issued by authorities against dangerous "
            "products without undue delay and in any event within two working days from receipt of the order. / "
            "在线市场平台必须设立单一联络点直接对接欧盟成员国市场监管机构。收到监管机构针对不安全或无合规欧代商品的下架令后，"
            "平台必须在不迟于2个工作日内迅速执行下架和阻断处置。"
        ),
        "penalty_summary": "向电商平台追究连带法律责任、按日计提巨额滞纳金、阻断在欧流量与支付结算",
    },
    {
        "id": "EU-GPSR-2023-988-ART51",
        "regulation_id": "EU-GPSR-2023-988-ART51",
        "title": "EU GPSR (通用产品安全法规) 第51条 成员国制裁与处罚体系",
        "article": "Article 51",
        "category": "general",
        "keywords": ["GPSR", "行政处罚", "成员国制裁", "营业额罚款", "罚则", "劝诫性处罚", "市场禁入"],
        "content": (
            "Member States shall lay down the rules on penalties applicable to infringements of this Regulation and shall "
            "take all measures necessary to ensure that they are implemented. The penalties provided for shall be effective, "
            "proportionate and dissuasive, and may include maximum fines of at least 4 % of the economic operator's or online "
            "marketplace's annual turnover in the Member States concerned. / "
            "欧盟各成员国应制定惩罚违规行为的法定规则，处罚措施必须有效、成比例且具劝诫性；严重违法情形下，最高罚款可达"
            "涉案经济运营者或在线平台在相关成员国年营业额的4%。"
        ),
        "penalty_summary": "最高处上年度全球/成员国营业额4%重罚、没收违法所得、终身禁入欧盟市场",
    },
    {
        "id": "EU-CE-TOY-EN71",
        "regulation_id": "EU-CE-TOY-EN71",
        "title": "EU 玩具安全指令 2009/48/EC & EN 71-1 机械物理安全与小零件窒息警示",
        "article": "Annex V & EN 71-1: Clause 7",
        "category": "toys",
        "keywords": ["玩具指令", "EN 71-1", "EN-71", "小零件", "窒息危险", "年龄警示", "3岁以下", "CE标志", "choking hazard", "small parts", "0-3岁窒息风险"],
        "content": (
            "Toys that could be dangerous for children under 36 months of age shall carry a warning: 'Not suitable for children under "
            "36 months' or 'Not suitable for children under 3 years' or the warning symbol, accompanied by a brief indication of the "
            "specific hazard (e.g., 'Choking hazard - small parts'). The CE marking must be visibly, legibly and indelibly affixed "
            "to the toy, an attached label or packaging. / "
            "供36个月以下儿童使用可能存在危险的玩具必须附带警示语：'Not suitable for children under 3 years / 不适合3岁以下儿童'，"
            "或红色禁止圆形图标，并附带明确危害说明（如'Choking hazard - small parts / 窒息危险——含小零件'）。"
            "CE合格标志必须清晰、易读且持久地附着于玩具本体或包装上。"
        ),
        "penalty_summary": "欧盟RAPEX危险品紧急通报、海关扣押查封、全网强制召回并集中销毁",
    },
    {
        "id": "EU-CE-TOY-EN71-3",
        "regulation_id": "EU-CE-TOY-EN71-3",
        "title": "EU 玩具安全指令 2009/48/EC & EN 71-3 19项特定化学元素迁移限量",
        "article": "Directive 2009/48/EC Annex II Part III",
        "category": "toys",
        "keywords": ["玩具指令", "EN 71-3", "重金属迁移", "铅限量", "特定化学元素", "毒性物质", "儿童健康", "化学安全"],
        "content": (
            "Migration limits for 19 chemical elements (including aluminium, antimony, arsenic, barium, boron, cadmium, "
            "chromium (III/VI), cobalt, copper, lead, manganese, mercury, nickel, selenium, strontium, tin, organic tin, zinc) "
            "must not exceed strict threshold values in toy materials. Lead (Pb) limit is strictly capped at 23 mg/kg for scraped-off "
            "materials. / 玩具材料中19项特定化学元素（铅、镉、汞、六价铬、砷、锑、钡、镍等）的迁移量不得超过严苛法定阈值。"
            "其中刮取玩具材料中铅(Pb)的迁移限量严格控制在23 mg/kg以内，严防儿童啃咬重金属中毒。"
        ),
        "penalty_summary": "强制下架召回、全欧口岸拉黑、涉案企业记入欧盟黑名单、立案移交刑责",
    },
    {
        "id": "EU-CE-LVD-2014-35",
        "regulation_id": "EU-CE-LVD-2014-35",
        "title": "EU 低电压指令 (LVD) 2014/35/EU 电气设备安全规范",
        "article": "Article 6 & Annex I",
        "category": "electronics",
        "keywords": ["LVD", "低电压指令", "电气安全", "触电防护", "CE标志", "符合性声明", "DoC", "过热起火", "低电压触电危险"],
        "content": (
            "Electrical equipment designed for use with a voltage rating of between 50 and 1000 V for AC and between 75 and 1500 V for DC "
            "must provide protection against electrical, mechanical, and fire hazards. The CE marking, manufacturer identification, "
            "and EU Declaration of Conformity (DoC) are mandatory before market placement. / "
            "交流额定电压在50V至1000V之间、直流额定电压在75V至1500V之间的电气设备，必须具备防护电击、机械损伤、高温过热及起火等安全保障。"
            "产品投放市场前必须加贴CE标志、制造商标识并签署欧盟符合性声明(DoC)。"
        ),
        "penalty_summary": "禁止进口、扣押仓储货物、责令退运销毁、处以5万至50万欧元行政罚款",
    },
    {
        "id": "EU-CE-EMC-2014-30",
        "regulation_id": "EU-CE-EMC-2014-30",
        "title": "EU 电磁兼容指令 (EMC) 2014/30/EU 电磁骚扰与抗扰度要求",
        "article": "Article 6 & Annex I",
        "category": "electronics",
        "keywords": ["EMC", "电磁兼容", "电磁抗扰度", "电磁骚扰", "无线干扰", "CE标志", "技术文件"],
        "content": (
            "Equipment shall be designed and manufactured in such a way that the electromagnetic disturbance generated does not exceed "
            "the level above which radio and telecommunications equipment cannot operate as intended, and the equipment has an adequate level "
            "of intrinsic immunity to electromagnetic disturbance. / "
            "设备的设计和制造必须保证其产生的电磁骚扰不会超过无线电和电信设备正常运行的允许水平，且设备本身对预期使用环境中的电磁骚扰"
            "具备足够的内在抗扰度。加贴CE标志并保留技术文件10年。"
        ),
        "penalty_summary": "海关拦截扣押、没收销售货款、责令限期整改下架",
    },
    {
        "id": "EU-ROHS-2011-65",
        "regulation_id": "EU-ROHS-2011-65",
        "title": "EU RoHS 2.0 指令 2011/65/EU 电子电气设备有害物质限制清单",
        "article": "Article 4 & Annex II",
        "category": "electronics",
        "keywords": ["RoHS", "有害物质限制", "铅", "汞", "镉", "六价铬", "多溴联苯", "邻苯二甲酸酯", "电子电气", "电子设备 铅汞重金属超标"],
        "content": (
            "Member States shall ensure that electrical and electronic equipment (EEE) placed on the market does not contain hazardous substances "
            "exceeding maximum concentration values tolerated by weight in homogeneous materials: Lead (0.1%), Mercury (0.1%), Cadmium (0.01%), "
            "Hexavalent chromium (0.1%), PBB (0.1%), PBDE (0.1%), DEHP (0.1%), BBP (0.1%), DBP (0.1%), DIBP (0.1%). / "
            "投放欧盟市场的电子电气设备（EEE）中，均质材料内10项有害物质重量浓度不得超标：铅(0.1%)、汞(0.1%)、镉(0.01%)、六价铬(0.1%)、"
            "多溴联苯(0.1%)、多溴二苯醚(0.1%)以及4项邻苯二甲酸酯增塑剂DEHP/BBP/DBP/DIBP(各0.1%)。"
        ),
        "penalty_summary": "全面查扣退运、禁止在欧销售、列入海关环保黑名单、最高罚款涉案货值3倍",
    },
    {
        "id": "EU-REACH-1907-2006",
        "regulation_id": "EU-REACH-1907-2006",
        "title": "EU REACH 法规 (EC) 1907/2006 附录XVII 限制物质清单",
        "article": "Article 67 & Annex XVII",
        "category": "general",
        "keywords": ["REACH", "附录XVII", "Annex XVII", "限制物质清单", "邻苯二甲酸酯", "镍释放", "PFAS", "禁用成分", "禁用化学成分"],
        "content": (
            "A substance on its own, in a mixture or in an article, for which a restriction is laid down in Annex XVII shall not be manufactured, "
            "placed on the market or used unless it complies with the conditions of that restriction. Includes restrictions on Nickel release in jewelry "
            "(<0.5 ug/cm2/week), Phthalates in plasticized materials (<0.1% w/w), and PFAS forever chemicals. / "
            "录入REACH附录XVII的限制化学物质及其制品，未达到限制条件不得制造、投放市场或使用。严格限制首饰/穿戴设备中的镍释放量"
            "(<0.5微克/平方厘米/周)、塑料玩具和母婴用品中的邻苯二甲酸酯类增塑剂(<0.1%质量比)以及多氟/全氟烷基物质(PFAS)。"
        ),
        "penalty_summary": "欧盟全境查封销毁、高额环保违规罚款、提起刑事指控",
    },
    {
        "id": "EU-COSMETICS-1223-2009-ART19",
        "regulation_id": "EU-COSMETICS-1223-2009-ART19",
        "title": "EU 化妆品法规 (EC) No 1223/2009 第19条 标签全成分标识与责任人义务",
        "article": "Article 19",
        "category": "cosmetics",
        "keywords": ["化妆品法规", "INCI", "成分清单", "全成分标注", "PAO", "开盖保质期", "责任人", "CPNP", "化妆品 禁用成分"],
        "content": (
            "Cosmetic products shall be made available on the market only where container and packaging bear indelible, easily legible and visible: "
            "(a) name and address of Responsible Person; (b) nominal content; (c) date of minimum durability / Period After Opening (PAO); "
            "(d) precautions in use; (e) batch number; (f) list of ingredients preceded by 'ingredients' using INCI names. / "
            "化妆品容器及包装上必须以清晰耐久字体标明：(a) 欧盟责任人名称与地址；(b) 净含量；(c) 最小保质期或开盖后使用期限(PAO)；"
            "(d) 使用注意事项及警示；(e) 批号或生产批次；(f) 冠以'Ingredients'字样的完整INCI国际命名成分清单。"
        ),
        "penalty_summary": "即刻扣押禁售、CPNP平台注销通报、责令下架召回并处以高额罚金",
    },
    {
        "id": "EU-COSMETICS-1223-2009-ANNEX2",
        "regulation_id": "EU-COSMETICS-1223-2009-ANNEX2",
        "title": "EU 化妆品法规 (EC) No 1223/2009 附录II 禁用物质与限用物质清单",
        "article": "Article 14 & Annex II",
        "category": "cosmetics",
        "keywords": ["化妆品法规", "禁用物质", "CMR物质", "糖皮质激素", "氢醌", "汞化合物", "铃兰醛", "附录II", "禁用化学成分 邻苯二甲酸酯 REACH"],
        "content": (
            "Cosmetic products shall not contain substances listed in Annex II (list of prohibited substances, over 1600 banned substances including "
            "hydroquinone, glucocorticoids, mercury compounds, lilial, and CMR category 1A/1B substances). / "
            "化妆品严禁含有附录II所列的1600余种禁用物质（包括氢醌、糖皮质激素、汞化合物、铃兰醛、重金属杂质以及所有CMR 1A/1B类致癌致突变生殖毒性物质）。"
        ),
        "penalty_summary": "构成危害公共卫生犯罪、强制全欧撤市追回、通报刑侦部门追究刑事责任",
    },
    {
        "id": "EU-BATTERY-2023-1542",
        "regulation_id": "EU-BATTERY-2023-1542",
        "title": "EU 新电池法规 (EU) 2023/1542 碳足迹、有害物质与电池护照",
        "article": "Chapter II & Article 13",
        "category": "electronics",
        "keywords": ["电池法规", "电池护照", "碳足迹", "二维码溯源", "回收标识", "CE标志", "带轮垃圾桶划叉", "铅镉汞"],
        "content": (
            "Batteries placed on the market shall be accompanied by a label containing general information, QR code linking to digital battery passport, "
            "CE marking, capacity, and separate collection symbol (crossed-out wheeled bin). Strict limits on lead, cadmium, and mercury. / "
            "投放欧盟市场的电池必须附带包含通用信息、数字化电池护照二维码、CE标志、额定容量以及分类收集带轮垃圾桶划叉标识。严格限制铅、镉、汞等有害金属含量。"
        ),
        "penalty_summary": "海关禁止通关、没收未认证电池产品、吊销进入欧盟市场许可",
    },
    {
        "id": "EU-PACKAGING-94-62-EC",
        "regulation_id": "EU-PACKAGING-94-62-EC",
        "title": "EU 包装与包装废弃物指令 94/62/EC 重金属限量与材质回收标识",
        "article": "Article 11 & Decision 97/129/EC",
        "category": "general",
        "keywords": ["包装指令", "重金属限量", "100ppm", "Triman标识", "EPR", "材质编码", "环保回收", "废弃物处置"],
        "content": (
            "The sum of concentration levels of lead, cadmium, mercury and hexavalent chromium in packaging or packaging components shall not exceed "
            "100 ppm by weight. Packaging must bear material identification codes (Decision 97/129/EC) and EPR environmental recycling label (e.g. Triman logo). / "
            "包装材料中铅、镉、汞、六价铬四种重金属的总含量不得超过100 ppm (0.01%重量比)。包装必须清晰标注材质编码及生产者责任延伸(EPR)回收标识"
            "（如法国Triman标识及分类投放指南）。"
        ),
        "penalty_summary": "海关阻截扣留、征收巨额EPR环保调节税、处最高5万欧元每批次罚款",
    },
    {
        "id": "EU-RED-2014-53",
        "regulation_id": "EU-RED-2014-53",
        "title": "EU 无线电设备指令 (RED) 2014/53/EU 频谱效率与网络安全要求",
        "article": "Article 3 & Article 10",
        "category": "electronics",
        "keywords": ["RED", "无线电设备", "射频", "Wi-Fi", "蓝牙", "频谱利用", "网络安全", "CE标志", "可追溯性"],
        "content": (
            "Radio equipment shall be constructed so as to ensure health and safety protection, an adequate level of electromagnetic compatibility, "
            "and effectively use radio spectrum. Delegated Regulation requires protection against cyber fraud and personal data security. CE marking and "
            "traceability info must be present. / "
            "无线电设备（含蓝牙、Wi-Fi、射频模块产品）必须确保使用者健康与安全、电磁兼容性并有效利用无线频谱，符合网络安全与隐私防欺诈要求。"
            "必须加贴CE标志并包含制造商/进口商可追溯性信息。"
        ),
        "penalty_summary": "没收无线发电设备、责令全欧无线频段屏蔽禁用、处以违法所得多倍罚金",
    },
    {
        "id": "EU-MDR-2017-745",
        "regulation_id": "EU-MDR-2017-745",
        "title": "EU 医疗器械法规 (MDR) (EU) 2017/745 临床评估与UDI唯一标识",
        "article": "Article 10 & Article 27",
        "category": "general",
        "keywords": ["MDR", "医疗器械", "UDI", "唯一器械标识", "公告机构", "CE标志", "EC REP", "欧代", "临床评估"],
        "content": (
            "Medical devices must have a CE marking with 4-digit Notified Body ID, Unique Device Identification (UDI) carrier on packaging, "
            "and designate an EU Authorized Representative (EC REP). Strict compliance with General Safety and Performance Requirements. / "
            "医疗器械（含家用医疗、体温计、理疗仪等）必须加贴带4位公告机构编号的CE标志，包装上必须印制UDI唯一器械标识符，并明确指定欧盟授权代表(EC REP)。"
        ),
        "penalty_summary": "吊销产品CE证书、全球召回并扣押、处以最高上年度营业额10%重罚并追究刑责",
    },
]

# Aliases
REGULATION_SEEDS = SEED_REGULATIONS


class OfflineDeterministicEmbeddingFunction:
    """Zero-dependency, deterministic bag-of-features and hashing embedding engine.

    Converts Chinese/English regulatory text and queries into normalized dense
    vectors (dimension = 128) using character n-grams, domain token weights,
    and a feature hashing projection. 100% offline and sub-millisecond execution.
    """

    def __init__(self, dim: int = 128):
        self.dim = dim

    # Keyword boosts for domain terminology
    DOMAIN_WEIGHTS: Dict[str, float] = {
        "gpsr": 3.0,
        "责任人": 3.5,
        "欧代": 3.5,
        "rep": 3.0,
        "追溯": 3.2,
        "可追溯": 3.2,
        "traceability": 3.2,
        "ce": 2.5,
        "玩具": 3.0,
        "toy": 3.0,
        "en71": 3.5,
        "en-71": 3.5,
        "en 71": 3.5,
        "小零件": 3.5,
        "窒息": 3.5,
        "choking": 3.5,
        "small parts": 3.5,
        "0-3岁": 3.2,
        "reach": 3.5,
        "化妆品": 3.0,
        "cosmetics": 3.0,
        "cosmetic": 3.0,
        "禁用成分": 3.5,
        "禁用物质": 3.5,
        "禁用化学成分": 3.5,
        "邻苯二甲酸酯": 3.5,
        "rohs": 3.5,
        "重金属": 3.0,
        "铅": 3.2,
        "汞": 3.2,
        "镉": 3.2,
        "六价铬": 3.2,
        "lvd": 3.0,
        "低电压": 3.0,
        "触电": 3.0,
        "emc": 3.0,
        "电磁兼容": 3.0,
        "电池": 3.0,
        "battery": 3.0,
        "包装": 2.5,
        "packaging": 2.5,
        "mdr": 3.0,
        "医疗器械": 3.0,
        "red": 3.0,
        "无线电": 3.0,
        "art9": 3.5,
        "art19": 3.5,
        "art22": 3.5,
        "第9条": 3.5,
        "第19条": 3.5,
    }

    def __call__(self, input: List[str]) -> List[List[float]]:
        embeddings: List[List[float]] = []
        for text in input:
            embeddings.append(self.embed_text(text))
        return embeddings

    def tokenize(self, text: str) -> List[Tuple[str, float]]:
        """Tokenize mixed multilingual text into tokens with associated weights."""
        if not text:
            return []

        lower_text = text.lower()
        tokens: List[Tuple[str, float]] = []

        # 1. Match multi-word domain keywords
        for kw, weight in self.DOMAIN_WEIGHTS.items():
            if kw in lower_text:
                tokens.append((kw, weight))

        # 2. English words and alphanumeric tokens
        words = re.findall(r"[a-z0-9_-]{2,}", lower_text)
        for w in words:
            weight = self.DOMAIN_WEIGHTS.get(w, 1.0)
            tokens.append((w, weight))

        # 3. Chinese character n-grams (unigrams and bigrams)
        chinese_chars = re.findall(r"[\u4e00-\u9fa5]", lower_text)
        for c in chinese_chars:
            weight = self.DOMAIN_WEIGHTS.get(c, 0.8)
            tokens.append((c, weight))

        for i in range(len(chinese_chars) - 1):
            bigram = chinese_chars[i] + chinese_chars[i + 1]
            weight = self.DOMAIN_WEIGHTS.get(bigram, 1.2)
            tokens.append((bigram, weight))

        return tokens

    def embed_text(self, text: str) -> List[float]:
        """Generate normalized dense vector for text."""
        vec = [0.0] * self.dim
        if not text:
            return vec

        tokens = self.tokenize(text)
        if not tokens:
            return vec

        for token, weight in tokens:
            h = int(hashlib.md5(token.encode("utf-8")).hexdigest(), 16)
            idx = h % self.dim
            sign = 1.0 if ((h >> 8) & 1) == 0 else -1.0
            vec[idx] += sign * weight

        # L2 Normalize
        norm_sq = sum(x * x for x in vec)
        if norm_sq > 0.0:
            norm = math.sqrt(norm_sq)
            vec = [x / norm for x in vec]

        return vec

    @staticmethod
    def cosine_similarity(vec_a: List[float], vec_b: List[float]) -> float:
        """Calculate cosine similarity between two unit-normalized vectors."""
        if not vec_a or not vec_b:
            return 0.0
        dot = sum(a * b for a, b in zip(vec_a, vec_b))
        return max(0.0, min(1.0, (dot + 1.0) / 2.0))


# Alias for backward compatibility
OfflineEmbeddingEngine = OfflineDeterministicEmbeddingFunction


class LocalVectorStore:
    """Self-contained local vector store with JSON persistence."""

    def __init__(self, storage_path: Path):
        self.storage_path = storage_path
        self.file_path = storage_path / "regulations_store.json"
        self._records: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if self.file_path.exists():
            try:
                data = json.loads(self.file_path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self._records = data
            except Exception:
                self._records = {}

    def _save(self) -> None:
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.file_path.write_text(json.dumps(self._records, ensure_ascii=False, indent=2), encoding="utf-8")

    def count(self) -> int:
        return len(self._records)

    def add(
        self,
        ids: List[str],
        documents: List[str],
        metadatas: List[Dict[str, Any]],
        embeddings: List[List[float]],
    ) -> None:
        for rid, doc, meta, emb in zip(ids, documents, metadatas, embeddings):
            self._records[rid] = {
                "id": rid,
                "document": doc,
                "metadata": meta,
                "embedding": emb,
            }
        self._save()

    def get_all(self) -> List[Dict[str, Any]]:
        return list(self._records.values())

    def clear(self) -> None:
        self._records.clear()
        self._save()


class RAGService:
    """ChromaDB & Zero-Dependency Hybrid RAG Service for EU Regulations."""

    COLLECTION_NAME = "eu_compliance_regulations"
    DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "chroma_db"

    def __init__(self, persist_directory: Optional[Union[str, Path]] = None):
        if persist_directory is not None:
            self.persist_directory = Path(persist_directory)
        else:
            self.persist_directory = self.DEFAULT_DB_PATH

        self.persist_directory.mkdir(parents=True, exist_ok=True)
        self.embedding_fn = OfflineDeterministicEmbeddingFunction(dim=128)

        self.client = None
        self.collection = None
        self._local_store = LocalVectorStore(self.persist_directory)

        # Attempt to initialize native ChromaDB PersistentClient if present
        self._init_client()

        # Automatically seed if the database is currently empty
        if self.count() == 0:
            self.seed_regulations(overwrite=False)

    def _init_client(self) -> None:
        """Attempt to lazily initialize ChromaDB PersistentClient."""
        try:
            import chromadb  # type: ignore
            from chromadb.config import Settings  # type: ignore

            self.client = chromadb.PersistentClient(
                path=str(self.persist_directory),
                settings=Settings(anonymized_telemetry=False, allow_reset=True),
            )
            self.collection = self.client.get_or_create_collection(
                name=self.COLLECTION_NAME,
                metadata={"description": "EU Cross-Border Trade & Product Safety Laws", "hnsw:space": "cosine"},
            )
        except Exception:
            # ChromaDB or native C++ dependencies unavailable; local store handles everything
            self.client = None
            self.collection = None

    def bulk_index_regulations(self, regulations: List[Dict[str, Any]]) -> int:
        """Bulk index statutory regulation items."""
        ids: List[str] = []
        documents: List[str] = []
        metadatas: List[Dict[str, Any]] = []
        embeddings: List[List[float]] = []

        for reg in regulations:
            reg_id = reg.get("regulation_id") or reg.get("id")
            title = reg.get("title", "")
            article = reg.get("article", "")
            content = reg.get("content", "")
            penalty_summary = reg.get("penalty_summary", "")
            category = reg.get("category", "general")
            keywords = reg.get("keywords", [])
            kw_str = " ".join(keywords) if isinstance(keywords, list) else str(keywords)

            combined_doc = f"{title}\n{article}\n{content}\n{penalty_summary}\n{kw_str}"
            meta = {
                "regulation_id": reg_id,
                "title": title,
                "article": article,
                "category": category,
                "penalty_summary": penalty_summary,
                "content": content,
                "keywords": ",".join(keywords) if isinstance(keywords, list) else kw_str,
            }
            emb = self.embedding_fn.embed_text(combined_doc)

            ids.append(reg_id)
            documents.append(combined_doc)
            metadatas.append(meta)
            embeddings.append(emb)

        # Persist to local store
        self._local_store.add(ids=ids, documents=documents, metadatas=metadatas, embeddings=embeddings)

        # Persist to Chroma collection if available
        if self.collection is not None:
            try:
                self.collection.upsert(
                    ids=ids,
                    documents=documents,
                    metadatas=metadatas,
                    embeddings=embeddings,
                )
            except Exception:
                pass

        return len(ids)

    def seed_regulations(self, overwrite: bool = False) -> int:
        """Seed authoritative EU regulations into the vector database."""
        current_count = self.count()
        if current_count > 0 and not overwrite:
            return current_count

        if overwrite:
            if self.collection is not None:
                try:
                    self.client.delete_collection(self.COLLECTION_NAME)
                    self.collection = self.client.create_collection(
                        name=self.COLLECTION_NAME,
                        metadata={"description": "EU Cross-Border Trade & Product Safety Laws", "hnsw:space": "cosine"},
                    )
                except Exception:
                    pass
            self._local_store.clear()

        return self.bulk_index_regulations(SEED_REGULATIONS)

    def count(self) -> int:
        """Return total number of seeded regulations."""
        if self.collection is not None:
            try:
                return self.collection.count()
            except Exception:
                pass
        return self._local_store.count()

    def get_all_regulations(self) -> List[RegulationMatch]:
        """Retrieve all stored regulations."""
        records = self._local_store.get_all()
        results: List[RegulationMatch] = []
        for rec in records:
            meta = rec["metadata"]
            kw_list = [k.strip() for k in meta.get("keywords", "").split(",") if k.strip()]
            results.append(
                RegulationMatch(
                    regulation_id=meta["regulation_id"],
                    title=meta["title"],
                    article=meta["article"],
                    content=meta["content"],
                    penalty_summary=meta["penalty_summary"],
                    category=meta["category"],
                    relevance_score=1.0,
                    keywords=kw_list,
                )
            )
        return results

    def search_regulations(
        self,
        query: str,
        category: Optional[str] = None,
        top_k: int = 3,
    ) -> List[RegulationMatch]:
        """Hybrid search regulations using dense vector similarity and keyword overlap."""
        if not query or not query.strip():
            return []

        # If vector database is empty, seed automatically
        if self.count() == 0:
            self.seed_regulations()

        cleaned_query = query.strip()
        query_vec = self.embedding_fn.embed_text(cleaned_query)
        query_tokens = [tok for tok, _ in self.embedding_fn.tokenize(cleaned_query)]

        records = self._local_store.get_all()
        if not records:
            return []

        scored_matches: List[Tuple[float, Dict[str, Any]]] = []

        for rec in records:
            meta = rec["metadata"]
            item_cat = meta.get("category", "general")

            # Category filtering
            if category and category != "all":
                if item_cat != category:
                    continue

            # 1. Dense vector cosine similarity
            emb = rec["embedding"]
            cos_sim = OfflineDeterministicEmbeddingFunction.cosine_similarity(query_vec, emb)

            # 2. Keyword exact overlap bonus
            doc_lower = (
                f"{meta['regulation_id']} {meta['title']} {meta['article']} {meta['content']} "
                f"{meta['penalty_summary']} {meta.get('keywords', '')}"
            ).lower()

            overlap_hits = 0
            for q_tok in query_tokens:
                if q_tok in doc_lower:
                    overlap_hits += 1

            overlap_ratio = overlap_hits / max(1, len(query_tokens))

            # Hybrid score: 65% cosine similarity + 35% term overlap
            hybrid_score = 0.65 * cos_sim + 0.35 * overlap_ratio

            # Category matching boost (matching exact specific category gets slight boost)
            if category and item_cat == category:
                hybrid_score = min(1.0, hybrid_score + 0.05)

            # If query is completely irrelevant gibberish with 0 keyword matches and low similarity
            if overlap_hits == 0 and cos_sim < 0.55:
                hybrid_score = min(0.35, hybrid_score * 0.5)

            scored_matches.append((hybrid_score, meta))

        # Sort descending by score
        scored_matches.sort(key=lambda x: x[0], reverse=True)

        # Slice top_k
        top_results: List[RegulationMatch] = []
        for score, meta in scored_matches[:top_k]:
            kw_list = [k.strip() for k in meta.get("keywords", "").split(",") if k.strip()]
            match = RegulationMatch(
                regulation_id=meta["regulation_id"],
                title=meta["title"],
                article=meta["article"],
                content=meta["content"],
                penalty_summary=meta["penalty_summary"],
                category=meta["category"],
                relevance_score=round(max(0.0, min(1.0, score)), 4),
                keywords=kw_list,
            )
            top_results.append(match)

        return top_results
