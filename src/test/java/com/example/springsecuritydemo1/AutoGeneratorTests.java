package com.example.springsecuritydemo1;

import com.baomidou.mybatisplus.generator.FastAutoGenerator;
import com.baomidou.mybatisplus.generator.config.OutputFile;
import com.baomidou.mybatisplus.generator.config.TemplateType;
import com.baomidou.mybatisplus.generator.engine.FreemarkerTemplateEngine;
import org.apache.ibatis.annotations.Mapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Collections;

@SpringBootTest
class AutoGeneratorTests {

    @Test
    void contextLoads() {
        FastAutoGenerator.create("jdbc:mysql://127.0.0.1:3306/springsecurity","root","root")
                .globalConfig(builder -> {
                    builder.author("myh") // 设置作者
                            .outputDir("F:\\javaStudy\\springsecurity-demo1\\src\\main\\java"); // 指定输出目录
                })
                .packageConfig(builder -> {
                    builder.parent("com.example.springsecuritydemo1") // 设置父包名
                            .moduleName("user") // 设置父包模块名
                            .entity("entity")
                            .service("service")
                            .serviceImpl("service.impl")
                            .mapper("mapper")
                            .xml("mapper.xml")
                            .controller("controller")
                            .pathInfo(Collections.singletonMap(OutputFile.xml, "F:\\javaStudy\\springsecurity-demo1\\src\\main\\resources\\mapper")); // 设置mapperXml生成路径
                })
                .templateConfig(builder -> {
                    builder.disable(TemplateType.ENTITY)
                            .entity("/templates/entity.java")
                            .service("/templates/service.java")
                            .serviceImpl("/templates/serviceImpl.java")
                            .mapper("/templates/mapper.java")
                            .controller("/templates/controller.java");
                })
                .strategyConfig(builder -> {
                    builder.controllerBuilder().enableRestStyle();
                    builder.entityBuilder().enableLombok();
                    builder.mapperBuilder().mapperAnnotation(Mapper.class);
                    builder.addInclude("sys_menu") // 设置需要生成的表名
                            .addInclude("sys_user_role").addInclude("sys_user").addInclude("sys_role").addInclude("sys_role_menu");
                    // .addTablePrefix("sys_"); // 设置过滤表前缀

                })
                .templateEngine(new FreemarkerTemplateEngine()) // 使用Freemarker引擎模板，默认的是Velocity引擎模板
                .execute();
    }

}
