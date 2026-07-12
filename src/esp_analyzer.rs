//! ESP 绘制与数据偏移分析模块
//!
//! 学习主流游戏 ESP 绘制方法，分析游戏数据结构，
//! 自动查找关键偏移量并生成代码。

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::common::types::ProcessId;
use crate::Result;

// ======================== 游戏数据结构定义 ========================

/// 游戏对象类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum GameObjectType {
    /// 玩家
    Player,
    /// 敌人
    Enemy,
    /// 队友
    Teammate,
    /// 物品/掉落物
    Item,
    /// 载具
    Vehicle,
    /// NPC
    NPC,
    /// 子弹/投射物
    Projectile,
    /// 其他
    Other(String),
}

/// 游戏对象数据结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameObject {
    /// 对象类型
    pub obj_type: GameObjectType,
    /// 基址
    pub base_address: u64,
    /// 对象名称
    pub name: String,
    /// 坐标 (x, y, z)
    pub position: Option<[f32; 3]>,
    /// 血量
    pub health: Option<f32>,
    /// 最大血量
    pub max_health: Option<f32>,
    /// 护甲
    pub armor: Option<f32>,
    /// 阵营/队伍
    pub team: Option<i32>,
    /// 状态标志
    pub flags: Option<u32>,
    /// 自定义属性
    pub properties: HashMap<String, PropertyValue>,
}

/// 属性值类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PropertyValue {
    Int(i64),
    Float(f32),
    Bool(bool),
    String(String),
    Vec3([f32; 3]),
    Bytes(Vec<u8>),
}

/// 偏移量定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Offset {
    /// 偏移名称
    pub name: String,
    /// 偏移值
    pub offset: u64,
    /// 数据类型
    pub data_type: DataType,
    /// 描述
    pub description: String,
    /// 置信度 (0-100)
    pub confidence: u8,
    /// 来源
    pub source: String,
}

/// 数据类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DataType {
    Int8,
    Int16,
    Int32,
    Int64,
    Float,
    Double,
    Bool,
    Vec2,
    Vec3,
    Vec4,
    String,
    Pointer,
    Bytes(usize),
}

/// ESP 绘制配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ESPConfig {
    /// 是否绘制玩家
    pub draw_players: bool,
    /// 是否绘制敌人
    pub draw_enemies: bool,
    /// 是否绘制队友
    pub draw_teammates: bool,
    /// 是否绘制物品
    pub draw_items: bool,
    /// 是否绘制血条
    pub draw_health_bar: bool,
    /// 是否绘制骨骼
    pub draw_skeleton: bool,
    /// 是否绘制方框
    pub draw_box: bool,
    /// 是否绘制名字
    pub draw_name: bool,
    /// 是否绘制距离
    pub draw_distance: bool,
    /// 是否绘制武器
    pub draw_weapon: bool,
    /// 最大绘制距离
    pub max_distance: f32,
    /// 敌人颜色 (RGBA)
    pub enemy_color: [f32; 4],
    /// 队友颜色
    pub teammate_color: [f32; 4],
    /// 物品颜色
    pub item_color: [f32; 4],
}

/// 游戏引擎类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GameEngine {
    /// Unreal Engine
    UnrealEngine,
    /// Unity
    Unity,
    /// Source Engine (CS:GO, Dota2等)
    Source,
    /// Frostbite (战地系列)
    Frostbite,
    /// id Tech (DOOM, Quake)
    IdTech,
    /// CryEngine
    CryEngine,
    /// 自定义引擎
    Custom(String),
    /// 未知
    Unknown,
}

/// 游戏配置模板
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameTemplate {
    /// 游戏名称
    pub game_name: String,
    /// 游戏引擎
    pub engine: GameEngine,
    /// 进程名
    pub process_name: String,
    /// 关键模块
    pub key_modules: Vec<String>,
    /// 已知偏移量
    pub offsets: Vec<Offset>,
    /// 对象遍历方法
    pub object_traversal: Option<ObjectTraversal>,
    /// 矩阵偏移（用于坐标转换）
    pub view_matrix_offset: Option<u64>,
    /// 本地玩家偏移
    pub local_player_offset: Option<u64>,
    /// 实体列表偏移
    pub entity_list_offset: Option<u64>,
    /// ESP 配置建议
    pub esp_config: ESPConfig,
    /// 备注
    pub notes: Vec<String>,
}

/// 对象遍历方法
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectTraversal {
    /// 遍历类型
    pub traversal_type: TraversalType,
    /// 列表基址
    pub list_base: u64,
    /// 对象大小
    pub object_size: usize,
    /// 最大对象数
    pub max_objects: usize,
    /// 下一个对象偏移（链表）
    pub next_offset: Option<u64>,
    /// 数组索引方式
    pub array_index: Option<u64>,
}

/// 遍历类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TraversalType {
    /// 数组遍历
    Array,
    /// 链表遍历
    LinkedList,
    /// 树遍历
    Tree,
    /// 哈希表
    HashMap,
    /// 自定义
    Custom(String),
}

// ======================== ESP 分析器 ========================

/// ESP 绘制分析器
#[allow(dead_code)]
pub struct ESPAnalyzer {
    pid: ProcessId,
    template: Option<GameTemplate>,
    discovered_offsets: Vec<Offset>,
    discovered_objects: Vec<GameObject>,
    analysis_results: Vec<AnalysisResult>,
}

/// 分析结果
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    /// 分析类型
    pub analysis_type: String,
    /// 结果描述
    pub result: String,
    /// 发现的偏移
    pub offsets: Vec<Offset>,
    /// 置信度
    pub confidence: u8,
}

impl ESPAnalyzer {
    /// 创建新的 ESP 分析器
    pub fn new(pid: ProcessId) -> Self {
        ESPAnalyzer {
            pid,
            template: None,
            discovered_offsets: Vec::new(),
            discovered_objects: Vec::new(),
            analysis_results: Vec::new(),
        }
    }

    /// 加载游戏模板
    pub fn load_template(&mut self, template: GameTemplate) {
        log::info!("加载游戏模板: {} ({:?})", template.game_name, template.engine);
        self.template = Some(template);
    }

    /// 分析游戏引擎类型
    pub fn detect_engine(&mut self) -> Result<GameEngine> {
        let mut engine = GameEngine::Unknown;
        
        // 通过模块名检测引擎
        #[cfg(unix)]
        {
            use crate::common::util::parse_proc_maps;
            if let Ok(regions) = parse_proc_maps(self.pid) {
                for region in &regions {
                    let name_lower = region.name.to_lowercase();
                    
                    if name_lower.contains("unreal") || name_lower.contains("ue4") || name_lower.contains("ue5") {
                        engine = GameEngine::UnrealEngine;
                        break;
                    } else if name_lower.contains("unity") || name_lower.contains("mono") {
                        engine = GameEngine::Unity;
                        break;
                    } else if name_lower.contains("source") || name_lower.contains("vphysics") {
                        engine = GameEngine::Source;
                        break;
                    } else if name_lower.contains("frostbite") {
                        engine = GameEngine::Frostbite;
                        break;
                    } else if name_lower.contains("idtech") {
                        engine = GameEngine::IdTech;
                        break;
                    } else if name_lower.contains("cryengine") {
                        engine = GameEngine::CryEngine;
                        break;
                    }
                }
            }
        }
        
        #[cfg(windows)]
        {
            use crate::inject::win_process;
            if let Ok(modules) = win_process::enum_modules(self.pid.0) {
                for m in &modules {
                    let name_lower = m.name.to_lowercase();
                    if name_lower.contains("unreal") || name_lower.contains("ue4") {
                        engine = GameEngine::UnrealEngine;
                        break;
                    } else if name_lower.contains("unity") || name_lower.contains("mono") {
                        engine = GameEngine::Unity;
                        break;
                    }
                }
            }
        }
        
        // 通过特征字符串进一步确认
        if engine == GameEngine::Unknown {
            #[cfg(unix)]
            {
                use crate::memory::MemoryScanner;
                let mut scanner = MemoryScanner::new(self.pid);
                
                if let Ok(addrs) = scanner.search_bytes(b"UE4", None) {
                    if !addrs.is_empty() {
                        engine = GameEngine::UnrealEngine;
                    }
                } else if let Ok(addrs) = scanner.search_bytes(b"UnityEngine", None) {
                    if !addrs.is_empty() {
                        engine = GameEngine::Unity;
                    }
                }
            }
        }
        
        log::info!("检测到游戏引擎: {:?}", engine);
        
        self.analysis_results.push(AnalysisResult {
            analysis_type: "引擎检测".to_string(),
            result: format!("检测到引擎: {:?}", engine),
            offsets: Vec::new(),
            confidence: 85,
        });
        
        Ok(engine)
    }

    /// 查找本地玩家对象
    #[cfg(unix)]
    pub fn find_local_player(&mut self) -> Result<Option<GameObject>> {
        log::info!("查找本地玩家对象...");
        
        // 根据模板或引擎类型查找
        if let Some(ref template) = self.template {
            if let Some(offset) = template.local_player_offset {
                return self.read_player_from_offset(offset);
            }
        }
        
        // 启发式查找
        self.heuristic_find_player()
    }

    /// 启发式查找玩家对象
    #[cfg(unix)]
    fn heuristic_find_player(&mut self) -> Result<Option<GameObject>> {
        use crate::memory::MemoryScanner;
        
        let mut scanner = MemoryScanner::new(self.pid);
        
        // 常见的本地玩家指针模式
        let patterns = vec![
            // Unity: GameLocalPlayer.Instance
            b"GameLocalPlayer" as &[u8],
            b"LocalPlayer" as &[u8],
            // Unreal: GetLocalPlayer
            b"GetLocalPlayer" as &[u8],
            // 通用
            b"LocalPlayerController" as &[u8],
            b"m_pLocalPlayer" as &[u8],
        ];
        
        for pattern in patterns {
            if let Ok(addrs) = scanner.search_bytes(pattern, None) {
                if !addrs.is_empty() {
                    log::info!("发现潜在玩家指针: {} @ {:?}", 
                        String::from_utf8_lossy(pattern), &addrs[..3.min(addrs.len())]);
                    
                    self.analysis_results.push(AnalysisResult {
                        analysis_type: "玩家查找".to_string(),
                        result: format!("发现潜在玩家指针: {:?}", &addrs[..3.min(addrs.len())]),
                        offsets: Vec::new(),
                        confidence: 60,
                    });
                }
            }
        }
        
        Ok(None)
    }

    /// 从偏移量读取玩家数据
    #[cfg(unix)]
    fn read_player_from_offset(&self, offset: u64) -> Result<Option<GameObject>> {
        // 实现读取逻辑
        Ok(None)
    }

    /// 分析对象结构
    #[cfg(unix)]
    pub fn analyze_object_structure(&mut self, address: u64) -> Result<Vec<Offset>> {
        use crate::memory::MemoryScanner;
        
        let mut scanner = MemoryScanner::new(self.pid);
        let data = scanner.dump_region(address, 1024)?;  // 读取 1KB 分析结构
        
        let mut offsets = Vec::new();
        
        // 启发式分析：查找浮点数（可能是坐标/血量）
        for i in (0..data.len() - 4).step_by(4) {
            let val = f32::from_le_bytes([data[i], data[i+1], data[i+2], data[i+3]]);
            
            // 检查是否像坐标值 (0-10000 范围)
            if val > 0.0 && val < 10000.0 && val.fract() != 0.0 {
                offsets.push(Offset {
                    name: format!("potential_float_{:x}", i),
                    offset: i as u64,
                    data_type: DataType::Float,
                    description: format!("可能的浮点值: {:.2}", val),
                    confidence: 40,
                    source: "启发式分析".to_string(),
                });
            }
            
            // 检查是否像血量值 (0-100 范围)
            if val > 0.0 && val <= 100.0 && val.fract() == 0.0 {
                offsets.push(Offset {
                    name: format!("potential_health_{:x}", i),
                    offset: i as u64,
                    data_type: DataType::Float,
                    description: format!("可能的血量值: {:.0}", val),
                    confidence: 50,
                    source: "启发式分析".to_string(),
                });
            }
        }
        
        // 检查指针值
        for i in (0..data.len() - 8).step_by(8) {
            let ptr = u64::from_le_bytes([
                data[i], data[i+1], data[i+2], data[i+3],
                data[i+4], data[i+5], data[i+6], data[i+7],
            ]);
            
            // 检查是否像有效指针
            if ptr > 0x10000 && ptr < 0x7FFFFFFFFFFF {
                offsets.push(Offset {
                    name: format!("potential_ptr_{:x}", i),
                    offset: i as u64,
                    data_type: DataType::Pointer,
                    description: format!("可能的指针: {:#x}", ptr),
                    confidence: 30,
                    source: "启发式分析".to_string(),
                });
            }
        }
        
        self.discovered_offsets.extend(offsets.clone());
        
        log::info!("分析对象结构 @ {:#x}: 发现 {} 个潜在偏移", address, offsets.len());
        
        Ok(offsets)
    }

    /// 生成 ESP 绘制代码
    pub fn generate_esp_code(&self, engine: &GameEngine) -> String {
        match engine {
            GameEngine::UnrealEngine => self.generate_unreal_esp(),
            GameEngine::Unity => self.generate_unity_esp(),
            GameEngine::Source => self.generate_source_esp(),
            _ => self.generate_generic_esp(),
        }
    }

    /// 生成 Unreal Engine ESP 代码
    fn generate_unreal_esp(&self) -> String {
        r#"
// Unreal Engine ESP 绘制代码
// 自动生成 - 请根据实际偏移量修改

class UE4ESP {
    constructor(pid) {
        this.pid = pid;
        // 从分析结果中获取的偏移量
        this.offsets = {
            localPlayer: 0x0,      // TODO: 填入实际偏移
            entityList: 0x0,       // TODO: 填入实际偏移
            playerState: 0x0,      // TODO: 填入实际偏移
            health: 0x0,           // TODO: 填入实际偏移
            position: 0x0,         // TODO: 填入实际偏移
            mesh: 0x0,             // TODO: 填入实际偏移
            rootComponent: 0x0,    // TODO: 填入实际偏移
        };
    }

    // 读取本地玩家
    readLocalPlayer() {
        // UE4: UGameInstance -> ULocalPlayer
        // 需要根据实际游戏逆向结果填写
    }

    // 遍历实体列表
    enumerateEntities() {
        // UE4: TArray 遍历
        // 需要根据实际游戏逆向结果填写
    }

    // 读取玩家坐标
    readPosition(entityAddr) {
        // UE4: AActor -> RootComponent -> RelativeLocation
        // 需要根据实际游戏逆向结果填写
    }

    // 读取血量
    readHealth(entityAddr) {
        // UE4: ACharacter -> Health
        // 需要根据实际游戏逆向结果填写
    }

    // 世界坐标转屏幕坐标
    worldToScreen(worldPos, viewMatrix) {
        // 标准 W2S 算法
        const clipCoords = {
            x: worldPos[0] * viewMatrix[0] + worldPos[1] * viewMatrix[4] + worldPos[2] * viewMatrix[8] + viewMatrix[12],
            y: worldPos[0] * viewMatrix[1] + worldPos[1] * viewMatrix[5] + worldPos[2] * viewMatrix[9] + viewMatrix[13],
            w: worldPos[0] * viewMatrix[3] + worldPos[1] * viewMatrix[7] + worldPos[2] * viewMatrix[11] + viewMatrix[15]
        };

        if (clipCoords.w < 0.1) return null;

        return {
            x: (1 + clipCoords.x / clipCoords.w) * screenWidth / 2,
            y: (1 - clipCoords.y / clipCoords.w) * screenHeight / 2
        };
    }
}
"#.to_string()
    }

    /// 生成 Unity ESP 代码
    fn generate_unity_esp(&self) -> String {
        r#"
// Unity ESP 绘制代码
// 自动生成 - 请根据实际偏移量修改

class UnityESP {
    constructor(pid) {
        this.pid = pid;
        // Unity/Mono 偏移量
        this.offsets = {
            gameAssembly: 0x0,     // GameAssembly.dll 基址
            localPlayer: 0x0,      // TODO: 填入实际偏移
            playerList: 0x0,       // TODO: 填入实际偏移
            transform: 0x0,        // Transform 组件偏移
            position: 0x0,         // localPosition 偏移
            health: 0x0,           // health 字段偏移
        };
    }

    // Unity Transform 读取坐标
    readPosition(transformAddr) {
        // Unity: Transform -> localPosition (Vector3)
        // 需要通过 il2cpp 获取实际偏移
    }

    // Unity 对象遍历
    enumerateGameObjects() {
        // Unity: List<T> 或 Array 遍历
        // 需要根据实际游戏逆向结果填写
    }
}
"#.to_string()
    }

    /// 生成 Source Engine ESP 代码
    fn generate_source_esp(&self) -> String {
        r#"
// Source Engine ESP 绘制代码
// CS:GO/Dota2 等游戏

class SourceESP {
    constructor(pid) {
        this.pid = pid;
        // Source Engine 常见偏移
        this.offsets = {
            localPlayer: 0x0,      // client.dll + dwLocalPlayer
            entityList: 0x0,       // client.dll + dwEntityList
            viewMatrix: 0x0,       // client.dll + dwViewMatrix
            health: 0x100,         // m_iHealth
            team: 0xF4,            // m_iTeamNum
            position: 0x138,       // m_vecOrigin
            dormant: 0xED,         // m_bDormant
            flags: 0x104,          // m_fFlags
            boneMatrix: 0x26A8,    // m_dwBoneMatrix
        };
    }

    // Source Engine 特有的遍历方式
    enumerateEntities() {
        // 通过 entityList + index * 0x10 遍历
    }

    // 读取骨骼数据用于绘制骨骼ESP
    readBones(entityAddr) {
        // 通过 m_dwBoneMatrix 读取骨骼坐标
    }
}
"#.to_string()
    }

    /// 生成通用 ESP 代码
    fn generate_generic_esp(&self) -> String {
        r#"
// 通用 ESP 绘制代码模板
// 需要根据具体游戏逆向结果填写偏移量

class GenericESP {
    constructor(pid) {
        this.pid = pid;
        this.offsets = {
            // TODO: 填入逆向分析得到的偏移量
            playerBase: 0x0,
            health: 0x0,
            position: 0x0,
            team: 0x0,
            name: 0x0,
        };
    }

    // 读取内存
    readMemory(address, size) {
        // 使用 frida-rust 的 read_memory
    }

    // 世界转屏幕
    worldToScreen(worldPos, viewMatrix) {
        // 通用 W2S 算法
    }

    // 绘制方框
    drawBox(x, y, w, h, color) {
        // 绘制矩形框
    }

    // 绘制血条
    drawHealthBar(x, y, health, maxHealth) {
        // 绘制血量条
    }

    // 绘制名字
    drawName(x, y, name) {
        // 绘制玩家名字
    }
}
"#.to_string()
    }

    /// 生成偏移量配置文件
    pub fn generate_offsets_json(&self) -> String {
        serde_json::to_string_pretty(&OffsetConfig {
            offsets: self.discovered_offsets.clone(),
            template: self.template.clone(),
        }).unwrap_or_default()
    }

    /// 获取分析报告
    pub fn report(&self) -> String {
        let mut report = String::from("=== ESP 分析报告 ===\n\n");
        
        if let Some(ref template) = self.template {
            report.push_str(&format!("🎮 游戏: {}\n", template.game_name));
            report.push_str(&format!("🔧 引擎: {:?}\n", template.engine));
            report.push_str(&format!("📁 进程: {}\n\n", template.process_name));
        }
        
        report.push_str(&format!("📊 分析结果: {} 条\n", self.analysis_results.len()));
        for result in &self.analysis_results {
            report.push_str(&format!("  • [{}%] {}: {}\n", 
                result.confidence, result.analysis_type, result.result));
        }
        
        report.push_str(&format!("\n🔍 发现的偏移量: {} 个\n", self.discovered_offsets.len()));
        for offset in self.discovered_offsets.iter().take(10) {
            report.push_str(&format!("  • {} @ {:#x} ({:?}) - {}\n",
                offset.name, offset.offset, offset.data_type, offset.description));
        }
        
        report
    }
}

/// 偏移量配置
#[derive(Debug, Serialize, Deserialize)]
struct OffsetConfig {
    offsets: Vec<Offset>,
    template: Option<GameTemplate>,
}

// ======================== 内置游戏模板 ========================

/// 获取内置游戏模板
pub fn builtin_templates() -> Vec<GameTemplate> {
    vec![
        // PUBG
        GameTemplate {
            game_name: "PUBG".to_string(),
            engine: GameEngine::UnrealEngine,
            process_name: "TslGame.exe".to_string(),
            key_modules: vec!["TslGame.exe".to_string(), "引擎模块".to_string()],
            offsets: vec![
                Offset {
                    name: "GNames".to_string(),
                    offset: 0x0,
                    data_type: DataType::Pointer,
                    description: "GNames 数组基址".to_string(),
                    confidence: 90,
                    source: "社区".to_string(),
                },
            ],
            object_traversal: Some(ObjectTraversal {
                traversal_type: TraversalType::Array,
                list_base: 0x0,
                object_size: 0x10,
                max_objects: 10000,
                next_offset: None,
                array_index: Some(0x0),
            }),
            view_matrix_offset: Some(0x0),
            local_player_offset: Some(0x0),
            entity_list_offset: Some(0x0),
            esp_config: ESPConfig {
                draw_players: true,
                draw_enemies: true,
                draw_teammates: false,
                draw_items: true,
                draw_health_bar: true,
                draw_skeleton: true,
                draw_box: true,
                draw_name: true,
                draw_distance: true,
                draw_weapon: true,
                max_distance: 1000.0,
                enemy_color: [1.0, 0.0, 0.0, 1.0],
                teammate_color: [0.0, 1.0, 0.0, 1.0],
                item_color: [1.0, 1.0, 0.0, 1.0],
            },
            notes: vec![
                "PUBG 使用 Unreal Engine 4".to_string(),
                "偏移量需要根据游戏版本更新".to_string(),
            ],
        },
        
        // 原神
        GameTemplate {
            game_name: "原神".to_string(),
            engine: GameEngine::Unity,
            process_name: "GenshinImpact.exe".to_string(),
            key_modules: vec!["GameAssembly.dll".to_string(), "UnityPlayer.dll".to_string()],
            offsets: vec![],
            object_traversal: None,
            view_matrix_offset: None,
            local_player_offset: None,
            entity_list_offset: None,
            esp_config: ESPConfig {
                draw_players: true,
                draw_enemies: true,
                draw_teammates: true,
                draw_items: true,
                draw_health_bar: true,
                draw_skeleton: false,
                draw_box: true,
                draw_name: true,
                draw_distance: true,
                draw_weapon: false,
                max_distance: 500.0,
                enemy_color: [1.0, 0.2, 0.2, 1.0],
                teammate_color: [0.2, 1.0, 0.2, 1.0],
                item_color: [1.0, 1.0, 0.2, 1.0],
            },
            notes: vec![
                "原神使用 Unity + IL2CPP".to_string(),
                "需要通过 GameAssembly.dll 获取偏移".to_string(),
                "米哈游反作弊检测严格，需要完整反检测".to_string(),
            ],
        },
        
        // CS:GO
        GameTemplate {
            game_name: "CS:GO".to_string(),
            engine: GameEngine::Source,
            process_name: "csgo.exe".to_string(),
            key_modules: vec!["client.dll".to_string(), "engine.dll".to_string()],
            offsets: vec![
                Offset {
                    name: "dwLocalPlayer".to_string(),
                    offset: 0x0,
                    data_type: DataType::Pointer,
                    description: "本地玩家指针".to_string(),
                    confidence: 95,
                    source: "社区".to_string(),
                },
                Offset {
                    name: "dwEntityList".to_string(),
                    offset: 0x0,
                    data_type: DataType::Pointer,
                    description: "实体列表".to_string(),
                    confidence: 95,
                    source: "社区".to_string(),
                },
                Offset {
                    name: "dwViewMatrix".to_string(),
                    offset: 0x0,
                    data_type: DataType::Pointer,
                    description: "视图矩阵".to_string(),
                    confidence: 95,
                    source: "社区".to_string(),
                },
            ],
            object_traversal: Some(ObjectTraversal {
                traversal_type: TraversalType::Array,
                list_base: 0x0,
                object_size: 0x10,
                max_objects: 64,
                next_offset: None,
                array_index: Some(0x10),
            }),
            view_matrix_offset: Some(0x0),
            local_player_offset: Some(0x0),
            entity_list_offset: Some(0x0),
            esp_config: ESPConfig {
                draw_players: true,
                draw_enemies: true,
                draw_teammates: true,
                draw_items: false,
                draw_health_bar: true,
                draw_skeleton: true,
                draw_box: true,
                draw_name: true,
                draw_distance: true,
                draw_weapon: true,
                max_distance: 5000.0,
                enemy_color: [1.0, 0.0, 0.0, 1.0],
                teammate_color: [0.0, 0.5, 1.0, 1.0],
                item_color: [1.0, 1.0, 0.0, 1.0],
            },
            notes: vec![
                "CS:GO 使用 Source Engine".to_string(),
                "偏移量可通过 https://github.com/frk1/hazedumper 获取".to_string(),
            ],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_esp_analyzer_creation() {
        let analyzer = ESPAnalyzer::new(ProcessId(1234));
        assert!(analyzer.template.is_none());
        assert!(analyzer.discovered_offsets.is_empty());
    }

    #[test]
    fn test_builtin_templates() {
        let templates = builtin_templates();
        assert!(!templates.is_empty());
        assert_eq!(templates[0].game_name, "PUBG");
    }

    #[test]
    fn test_generate_esp_code() {
        let analyzer = ESPAnalyzer::new(ProcessId(1234));
        let code = analyzer.generate_esp_code(&GameEngine::UnrealEngine);
        assert!(code.contains("UE4"));
    }
}
